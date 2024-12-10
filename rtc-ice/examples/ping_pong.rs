use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::Uri;
use hyper::{body::Incoming as Body, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use lazy_static::lazy_static;
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::agent::Agent;
use rtc_ice::state::ConnectionState;
use rtc_ice::{Credentials, Event};
use shared::{Protocol, Transmit, TransportContext};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

type SenderType = Arc<Mutex<mpsc::Sender<String>>>;
type ReceiverType = Arc<Mutex<mpsc::Receiver<String>>>;

lazy_static! {
    static ref REMOTE_AUTH_CHANNEL: (SenderType, ReceiverType) = create_channel(3);
    static ref REMOTE_CAND_CHANNEL: (SenderType, ReceiverType) = create_channel(10);
}

fn create_channel(capacity: usize) -> (SenderType, ReceiverType) {
    let (tx, rx) = mpsc::channel::<String>(capacity);
    (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
}

#[derive(Parser)]
#[command(name = "ICE Ping Pong")]
struct Cli {
    #[arg(short, long)]
    controlling: bool,

    #[arg(short, long)]
    debug: bool,

    #[arg(long, default_value_t = String::from("INFO"))]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    initialize_logging(&cli)?;

    let (local_http_port, remote_http_port) = determine_ports(cli.controlling);
    let udp_socket = initialize_udp_socket(cli.controlling).await?;
    let local_addr = udp_socket
        .local_addr()
        .context("Failed to get local address")?;
    println!("UDP socket bound to {}", local_addr);

    let mut ice_agent = initialize_ice_agent()?;
    start_http_server(local_http_port).await;

    wait_for_remote_ready(remote_http_port)
        .await
        .context("Failed to wait for remote server readiness")?;

    handle_ice_negotiation(&mut ice_agent, remote_http_port, cli.controlling).await?;
    monitor_agent_events(&mut ice_agent, &udp_socket).await?;

    Ok(())
}

fn initialize_logging(cli: &Cli) -> Result<()> {
    if cli.debug {
        let log_level =
            log::LevelFilter::from_str(&cli.log_level).unwrap_or(log::LevelFilter::Info);
        env_logger::Builder::new().filter(None, log_level).init();
    }
    Ok(())
}

fn determine_ports(controlling: bool) -> (u16, u16) {
    if controlling {
        (9000, 9001)
    } else {
        (9001, 9000)
    }
}

async fn initialize_udp_socket(controlling: bool) -> Result<UdpSocket> {
    let port = if controlling { 4000 } else { 4001 };
    println!("Binding UDP socket on port {}", port);
    UdpSocket::bind(("0.0.0.0", port))
        .await
        .context("Failed to bind UDP socket")
}

fn initialize_ice_agent() -> Result<Agent> {
    Agent::new(Arc::new(AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    }))
    .context("Failed to initialize ICE agent")
}

async fn start_http_server(local_http_port: u16) {
    tokio::spawn(async move {
        let addr: SocketAddr = ([0, 0, 0, 0], local_http_port).into();
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("Failed to bind HTTP server listener: {}", e);
                return;
            }
        };

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            tokio::spawn(async move {
                let service = hyper::service::service_fn(remote_handler);
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("Error serving connection: {}", e);
                }
            });
        }
    });
}

async fn remote_handler(
    req: Request<Body>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, anyhow::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/remoteAuth") => handle_remote_auth(req).await,
        (&Method::POST, "/remoteCandidate") => handle_remote_candidate(req).await,
        (&Method::GET, "/health") => handle_health_check().await,
        _ => {
            eprintln!("404 Not Found: {} {}", req.method(), req.uri().path());
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Empty::new().boxed())
                .context("Failed to build response for 404 Not Found")?)
        }
    }
}
async fn handle_remote_auth(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, anyhow::Error> {
    // Attempt to collect the body and convert it to a string
    let body_bytes = match req.into_body().collect().await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to collect request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Empty::new().boxed())
                .context("Failed to build response for body collection error")?);
        }
    };

    let message = match String::from_utf8(body_bytes.to_bytes().into()) {
        Ok(message) => message,
        Err(e) => {
            eprintln!("Failed to convert body to string: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Empty::new().boxed())
                .context("Failed to build response for string conversion error")?);
        }
    };

    // Attempt to send the message to the queue
    let tx = REMOTE_AUTH_CHANNEL.0.lock().await;
    match tx.send(message).await {
        Ok(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Empty::new().boxed())
            .context("Failed to build success response")?),
        Err(e) => {
            eprintln!("Failed to send auth to peer: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Empty::new().boxed())
                .context("Failed to build response for queue error")?)
        }
    }
}

async fn handle_remote_candidate(
    req: Request<Body>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, anyhow::Error> {
    // Attempt to collect the body and convert it to a string
    let body_bytes = match req.into_body().collect().await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to collect request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Empty::new().boxed())
                .context("Failed to build response for body collection error")?);
        }
    };

    let message = match String::from_utf8(body_bytes.to_bytes().into()) {
        Ok(message) => message,
        Err(e) => {
            eprintln!("Failed to convert body to string: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Empty::new().boxed())
                .context("Failed to build response for string conversion error")?);
        }
    };

    // Attempt to send the message to the queue
    let tx = REMOTE_CAND_CHANNEL.0.lock().await;
    match tx.send(message).await {
        Ok(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Empty::new().boxed())
            .context("Failed to build success response")?),
        Err(e) => {
            eprintln!("Failed to send candidate to peer: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Empty::new().boxed())
                .context("Failed to build response for queue error")?)
        }
    }
}

/// Handles the health check route.
async fn handle_health_check() -> Result<Response<BoxBody<Bytes, Infallible>>, anyhow::Error> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Empty::new().boxed())
        .context("Failed to build health check response")
}

async fn handle_ice_negotiation(
    ice_agent: &mut Agent,
    remote_http_port: u16,
    controlling: bool,
) -> Result<()> {
    // Retrieve local ICE credentials
    let Credentials { ufrag, pwd } = ice_agent.get_local_credentials();
    println!("Local ICE Credentials: ufrag={}, pwd={}", ufrag, pwd);

    // Send local credentials to remote peer
    send_local_credentials(remote_http_port, &ufrag, &pwd).await?;

    // Receive remote credentials from peer
    let (remote_ufrag, remote_pwd) = receive_remote_credentials().await?;
    println!(
        "Received remote credentials: ufrag={}, pwd={}",
        remote_ufrag, remote_pwd
    );

    // Start ICE connectivity checks
    start_connectivity_checks(ice_agent, controlling, &remote_ufrag, &remote_pwd)?;

    Ok(())
}

async fn send_local_credentials(remote_http_port: u16, ufrag: &str, pwd: &str) -> Result<()> {
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let uri = format!("http://localhost:{}/remoteAuth", remote_http_port);
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(format!("{}:{}", ufrag, pwd))
        .context("Failed to build request for sending local credentials")?;

    client
        .request(req)
        .await
        .context("Failed to send local credentials to remote peer")?;

    println!("Local credentials sent to remote peer");
    Ok(())
}

fn start_connectivity_checks(
    ice_agent: &mut Agent,
    controlling: bool,
    remote_ufrag: &str,
    remote_pwd: &str,
) -> Result<()> {
    ice_agent
        .start_connectivity_checks(
            controlling,
            remote_ufrag.to_string(),
            remote_pwd.to_string(),
        )
        .context("Failed to start ICE connectivity checks")?;

    println!("ICE connectivity checks started");
    Ok(())
}

async fn receive_remote_credentials() -> Result<(String, String)> {
    let mut rx = REMOTE_AUTH_CHANNEL.1.lock().await;
    if let Some(message) = rx.recv().await {
        let parts: Vec<_> = message.split(':').collect();
        if parts.len() == 2 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        }
    }
    Err(anyhow::anyhow!("Failed to receive remote credentials"))
}

async fn monitor_agent_events(
    ice_agent: &mut Agent,
    udp_socket: &UdpSocket,
) -> Result<(), anyhow::Error> {
    let mut buf = vec![0u8; 2048];

    loop {
        // Process outgoing transmissions from the ICE agent
        process_transmissions(ice_agent, udp_socket).await?;

        // Process ICE agent events
        if process_ice_events(ice_agent).await? {
            println!("Connection failed, exiting loop.");
            break;
        }

        // Handle ICE timeouts
        handle_ice_timeouts(ice_agent).await;

        // Process incoming UDP packets
        if let Ok((size, addr)) = udp_socket.recv_from(&mut buf).await {
            if size > 0 {
                process_incoming_packet(ice_agent, udp_socket, &buf[..size], addr).await?;
            }
        }
    }

    Ok(())
}

/// Processes outgoing transmissions from the ICE agent.
async fn process_transmissions(
    ice_agent: &mut Agent,
    udp_socket: &UdpSocket,
) -> Result<(), anyhow::Error> {
    while let Some(transmit) = ice_agent.poll_transmit() {
        println!(
            "Sending {} bytes to {}",
            transmit.message.len(),
            transmit.transport.peer_addr
        );
        udp_socket
            .send_to(&transmit.message[..], transmit.transport.peer_addr)
            .await
            .context("Failed to send ICE transmission")?;
    }
    Ok(())
}

/// Processes ICE agent events and handles state changes.
async fn process_ice_events(ice_agent: &mut Agent) -> Result<bool, anyhow::Error> {
    let mut is_failed = false;

    while let Some(event) = ice_agent.poll_event() {
        match event {
            Event::ConnectionStateChange(cs) => {
                println!("ConnectionStateChange: {}", cs);
                if cs == ConnectionState::Failed {
                    is_failed = true;
                }
            }
            _ => {
                println!(
                    "Unhandled ICE agent event of type: {}",
                    std::any::type_name::<Event>()
                );
            }
        }
    }

    Ok(is_failed)
}

/// Handles ICE agent timeouts.
async fn handle_ice_timeouts(ice_agent: &mut Agent) {
    if let Some(timeout) = ice_agent.poll_timeout() {
        let duration = timeout.duration_since(Instant::now());
        tokio::time::sleep(duration).await;
        ice_agent.handle_timeout(Instant::now());
    }
}

/// Processes incoming UDP packets, checking for STUN messages or other data.
async fn process_incoming_packet(
    ice_agent: &mut Agent,
    udp_socket: &UdpSocket,
    buf: &[u8],
    addr: std::net::SocketAddr,
) -> Result<(), anyhow::Error> {
    if stun::message::is_message(buf) {
        println!("Received STUN message from {}", addr);
        ice_agent.handle_read(Transmit::<BytesMut> {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: udp_socket.local_addr()?,
                peer_addr: addr,
                ecn: None,
                protocol: Protocol::UDP,
            },
            message: BytesMut::from(buf),
        })?;
    } else {
        println!(
            "Received non-STUN message from {}: {}",
            addr,
            String::from_utf8_lossy(buf)
        );
    }
    Ok(())
}

/// Waits for the remote server to become available before proceeding.
async fn wait_for_remote_ready(remote_http_port: u16) -> Result<()> {
    let host = "127.0.0.1";
    let addr = format!("{}:{}", host, remote_http_port);
    let uri: Uri = format!("http://{}/health", addr)
        .parse()
        .context("Failed to parse health check URI")?;

    for attempt in 1..=10 {
        match attempt_connection(&addr, &uri).await {
            Ok(()) => {
                println!("Remote server is ready after {} attempts.", attempt);
                return Ok(());
            }
            Err(e) => {
                println!(
                    "Attempt {}/10 failed: {}. Retrying in 1 second...",
                    attempt, e
                );
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to connect to remote server after 10 attempts."
    ))
}

/// Attempts to connect to the server and send a health check request.
async fn attempt_connection(addr: &str, uri: &Uri) -> Result<()> {
    let stream = TcpStream::connect(addr)
        .await
        .context(format!("Failed to connect to {}", addr))?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake failed")?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("Connection failed: {:?}", err);
        }
    });

    let authority = uri.authority().unwrap().clone();
    let req = Request::builder()
        .uri(uri.path())
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())
        .context("Failed to build health check request")?;

    let res = sender
        .send_request(req)
        .await
        .context("Failed to send health check request")?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Health check failed with status: {}",
            res.status()
        ))
    }
}
