use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::Uri;
use hyper::{body::Incoming as Body, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::agent::Agent;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::{Candidate, CandidateConfig};
use rtc_ice::state::ConnectionState;
use rtc_ice::{Credentials, Event};
use shared::{Protocol, Transmit, TransportContext};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::message::Message;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{self};

pub enum IceCommand {
    RemoteCredentials { ufrag: String, pwd: String },
    RemoteCandidate(String),
    UdpPacket { data: BytesMut, addr: SocketAddr },
}

pub struct IceManager {
    agent: Agent,
    socket: UdpSocket,
    command_rx: mpsc::Receiver<IceCommand>,
    controlling: bool,
}

impl IceManager {
    pub fn new(
        agent: Agent,
        socket: UdpSocket,
        command_rx: mpsc::Receiver<IceCommand>,
        controlling: bool,
    ) -> Self {
        Self {
            agent,
            socket,
            command_rx,
            controlling,
        }
    }

    fn create_local_candidate(&mut self) -> Result<Candidate> {
        let local_addr = self
            .socket
            .local_addr()
            .context("Failed to get local socket address")?;

        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .context("Failed to create host candidate")?;

        self.agent.add_local_candidate(candidate.clone())?;

        Ok(candidate)
    }

    pub fn get_local_credentials(&self) -> &Credentials {
        self.agent.get_local_credentials()
    }

    pub async fn spawn(
        mut self,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        Ok(tokio::spawn(async move {
            let result = self.run(&mut shutdown).await;
            println!("IceManager shutdown complete");
            result
        }))
    }

    async fn run(&mut self, shutdown: &mut broadcast::Receiver<()>) -> Result<()> {
        let mut tick_interval = time::interval(Duration::from_millis(100));
        let mut buf = vec![0u8; 2048];

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    println!("IceManager received shutdown signal");
                    break;
                }

                Some(command) = self.command_rx.recv() => {
                    self.handle_command(command).await?;
                }

                _ = tick_interval.tick() => {
                    self.handle_tick().await?;
                }

                recv_result = self.socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((size, addr)) if size > 0 => {
                            self.handle_udp_packet(&buf[..size], addr).await?;
                        }
                        Ok(_) => (),
                        Err(e) => println!("UDP receive error: {}", e),
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, command: IceCommand) -> Result<()> {
        match command {
            IceCommand::RemoteCredentials { ufrag, pwd } => {
                println!("Received remote credentials: ufrag={}, pwd={}", ufrag, pwd);
                self.agent
                    .start_connectivity_checks(self.controlling, ufrag, pwd)
                    .context("Failed to start connectivity checks")?;
            }

            IceCommand::RemoteCandidate(cand_str) => {
                match rtc_ice::candidate::unmarshal_candidate(&cand_str) {
                    Ok(candidate) => {
                        println!("Adding remote candidate: {}", cand_str);
                        self.agent
                            .add_remote_candidate(candidate)
                            .context("Failed to add remote candidate")?;
                    }
                    Err(e) => println!("Failed to parse remote candidate: {}", e),
                }
            }

            IceCommand::UdpPacket { data, addr } => {
                self.agent
                    .handle_read(Transmit {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.socket.local_addr()?,
                            peer_addr: addr,
                            ecn: None,
                            protocol: Protocol::UDP,
                        },
                        message: data,
                    })
                    .context("Failed to handle UDP packet")?;
            }
        }
        Ok(())
    }

    async fn handle_tick(&mut self) -> Result<()> {
        // Handle outgoing transmissions
        while let Some(transmit) = self.agent.poll_transmit() {
            self.socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await
                .context("Failed to send ICE transmission")?;
        }

        // Handle ICE timeouts
        if let Some(timeout) = self.agent.poll_timeout() {
            if Instant::now() >= timeout {
                self.agent.handle_timeout(Instant::now());
            }
        }

        // Process ICE events
        while let Some(event) = self.agent.poll_event() {
            match event {
                Event::ConnectionStateChange(state) => {
                    println!("ICE Connection State Changed: {}", state);
                    match state {
                        ConnectionState::Completed => {
                            if let Some((local, remote)) = self.agent.get_selected_candidate_pair()
                            {
                                println!("Selected local candidate: {:?}", local.addr());
                                println!("Selected remote candidate: {:?}", remote.addr());
                            }
                        }
                        ConnectionState::Failed => {
                            println!("ICE negotiation failed");
                            return Err(anyhow::anyhow!("ICE negotiation failed"));
                        }
                        ConnectionState::Closed => {
                            println!("ICE agent closed");
                            return Ok(());
                        }
                        _ => {
                            println!("ICE agent state changed: {:?}", state);
                        }
                    }
                }
                Event::SelectedCandidatePairChange(local, remote) => {
                    println!("Selected candidate pair changed:");
                    println!("Local: {:?}", local.addr());
                    println!("Remote: {:?}", remote.addr());
                }
            }
        }

        Ok(())
    }

    async fn handle_udp_packet(&mut self, data: &[u8], addr: SocketAddr) -> Result<()> {
        if stun::message::is_message(data) {
            let mut message = Message::new();
            message
                .unmarshal_binary(data)
                .context("Failed to unmarshal STUN message")?;
            println!("Received STUN message from {}", message);
            self.agent
                .handle_read(Transmit {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: self.socket.local_addr()?,
                        peer_addr: addr,
                        ecn: None,
                        protocol: Protocol::UDP,
                    },
                    message: BytesMut::from(data),
                })
                .context("Failed to handle STUN message")?;
        } else {
            println!(
                "Received non-STUN message from {}: {}",
                addr,
                String::from_utf8_lossy(data)
            );
        }
        Ok(())
    }
}

pub struct HttpServer {
    listener: TcpListener,
    ice_tx: mpsc::Sender<IceCommand>,
}

impl HttpServer {
    pub async fn new(addr: SocketAddr, ice_tx: mpsc::Sender<IceCommand>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context("Failed to bind HTTP server")?;

        println!("HTTP server listening on {}", addr);

        Ok(Self { listener, ice_tx })
    }

    pub async fn spawn(
        self,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        Ok(tokio::spawn(async move {
            let result = self.run(&mut shutdown).await;
            println!("HTTP server shutdown complete");
            result
        }))
    }

    async fn run(&self, shutdown: &mut broadcast::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    println!("HTTP server received shutdown signal");
                    break;
                }

                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, _)) => {
                            let ice_tx = self.ice_tx.clone();
                            tokio::spawn(async move {
                                let service = hyper::service::service_fn(move |req| {
                                    let ice_tx = ice_tx.clone();
                                    async move {
                                        handle_request(req, ice_tx).await
                                    }
                                });

                                if let Err(e) = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(TokioIo::new(stream), service)
                                    .await
                                {
                                    println!("Error serving connection: {}", e);
                                }
                            });
                        }
                        Err(e) => println!("Error accepting connection: {}", e),
                    }
                }
            }
        }

        Ok(())
    }
}

type ResponseType = Response<BoxBody<Bytes, std::convert::Infallible>>;

async fn handle_request(
    req: Request<Body>,
    ice_tx: mpsc::Sender<IceCommand>,
) -> Result<ResponseType, anyhow::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/remoteAuth") => handle_remote_auth(req, ice_tx).await,
        (&Method::POST, "/remoteCandidate") => handle_remote_candidate(req, ice_tx).await,
        (&Method::GET, "/health") => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Empty::new().boxed())
            .context("Failed to build health check response")?),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Empty::new().boxed())
            .context("Failed to build 404 response")?),
    }
}

async fn handle_remote_auth(
    req: Request<Body>,
    ice_tx: mpsc::Sender<IceCommand>,
) -> Result<ResponseType, anyhow::Error> {
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("Failed to read request body")?
        .to_bytes();

    let message =
        String::from_utf8(body_bytes.to_vec()).context("Failed to parse body as UTF-8")?;

    let parts: Vec<_> = message.split(':').collect();
    if parts.len() != 2 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Empty::new().boxed())
            .context("Failed to build bad request response")?);
    }

    ice_tx
        .send(IceCommand::RemoteCredentials {
            ufrag: parts[0].to_string(),
            pwd: parts[1].to_string(),
        })
        .await
        .context("Failed to send credentials to ICE manager")?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Empty::new().boxed())
        .context("Failed to build success response")?)
}

async fn handle_remote_candidate(
    req: Request<Body>,
    ice_tx: mpsc::Sender<IceCommand>,
) -> Result<ResponseType, anyhow::Error> {
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("Failed to read request body")?
        .to_bytes();

    let candidate =
        String::from_utf8(body_bytes.to_vec()).context("Failed to parse body as UTF-8")?;

    ice_tx
        .send(IceCommand::RemoteCandidate(candidate))
        .await
        .context("Failed to send candidate to ICE manager")?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Empty::new().boxed())
        .context("Failed to build success response")?)
}

#[derive(Parser)]
#[command(name = "ICE Ping Pong")]
pub struct Cli {
    #[arg(short, long)]
    controlling: bool,

    #[arg(short, long)]
    debug: bool,

    #[arg(long, default_value_t = String::from("INFO"))]
    log_level: String,
}

pub struct App {
    ice_manager: IceManager,
    http_server: HttpServer,
    shutdown_tx: broadcast::Sender<()>,
    controlling: bool,
}

impl App {
    pub async fn new(cli: &Cli) -> Result<Self> {
        // Initialize channels
        let (ice_tx, ice_rx) = mpsc::channel::<IceCommand>(32);
        let (shutdown_tx, _) = broadcast::channel(1);

        // Initialize UDP socket
        let socket = initialize_udp_socket(cli.controlling).await?;
        println!("UDP socket bound to {}", socket.local_addr()?);

        // Initialize ICE agent
        let agent = initialize_ice_agent()?;

        // Initialize components
        let ice_manager = IceManager::new(agent, socket, ice_rx, cli.controlling);

        let http_server = HttpServer::new(determine_http_addr(cli.controlling)?, ice_tx).await?;

        Ok(Self {
            ice_manager,
            http_server,
            shutdown_tx,
            controlling: cli.controlling,
        })
    }

    pub async fn run(self) -> Result<()> {
        let App {
            mut ice_manager,
            http_server,
            shutdown_tx,
            controlling,
        } = self;
        // First spawn the HTTP server so others can connect
        let http_handle = http_server.spawn(shutdown_tx.subscribe()).await?;

        // Then wait for the remote peer's HTTP server
        // Use controlling directly since we moved it out
        let remote_port = if self.controlling { 9001 } else { 9000 };
        let uri = format!("http://127.0.0.1:{}/health", remote_port);

        // Try to connect to remote
        for attempt in 1..=10 {
            match attempt_health_check(&uri).await {
                Ok(()) => {
                    println!("Remote server is ready");
                    break;
                }
                Err(e) => {
                    println!("Attempt {}/10 failed: {}", attempt, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        let credentials = ice_manager.get_local_credentials().clone();
        let local_candidate = ice_manager.create_local_candidate()?;

        // Then spawn the ICE manager, which will set up local candidates
        let mut ice_handle = ice_manager.spawn(shutdown_tx.subscribe()).await?;

        // Send our credentials to remote peer
        send_credentials_to_remote(&credentials, controlling).await?;
        send_candidate_to_remote(&local_candidate, controlling).await?;

        let mut ice_done = false;

        // Wait for shutdown signal
        tokio::select! {
            // If the ICE manager finishes first, handle its result
            ice_result = &mut ice_handle => {
                ice_done = true;

                match ice_result {
                    Ok(Ok(())) => println!("ICE Manager completed successfully"),
                    Ok(Err(e)) => {
                        println!("ICE Manager encountered an error: {}", e);
                    },
                    Err(join_error) => {
                        println!("ICE Manager task panicked: {}", join_error);
                    }
                }
                // In any case, we can signal shutdown since ICE manager is done
                let _ = shutdown_tx.send(());
            }

            // If CTRL+C is pressed first, we trigger a graceful shutdown
            _ = signal::ctrl_c() => {
                println!("Received CTRL+C, initiating graceful shutdown...");
                let _ = shutdown_tx.send(());
            }
        }

        if !ice_done {
            // If ICE wasn't done yet, now we can await ice_handle.
            match ice_handle.await {
                Ok(Ok(())) => println!("ICE Manager completed successfully"),
                Ok(Err(e)) => println!("ICE Manager encountered an error: {}", e),
                Err(join_error) => println!("ICE Manager panicked: {}", join_error),
            }
        }
        // Wait for https server to shut down
        // Now await the HTTP server
        match http_handle.await {
            Ok(Ok(())) => println!("HTTP server shut down gracefully"),
            Ok(Err(e)) => {
                println!("HTTP server encountered an error: {}", e);
            }
            Err(join_error) => {
                println!("HTTP server task panicked: {}", join_error);
            }
        }

        println!("All components shut down successfully");
        Ok(())
    }
}

async fn send_credentials_to_remote(credentials: &Credentials, controlling: bool) -> Result<()> {
    let remote_port = if controlling { 9001 } else { 9000 };
    let uri = format!("http://127.0.0.1:{}/remoteAuth", remote_port);
    let body = format!("{}:{}", credentials.ufrag, credentials.pwd);

    let stream = TcpStream::connect(format!("127.0.0.1:{}", remote_port)).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake failed")?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(hyper::header::HOST, format!("127.0.0.1:{}", remote_port))
        .body(body)
        .context("Failed to build credentials request")?;

    sender.send_request(req).await?;
    Ok(())
}

async fn send_candidate_to_remote(candidate: &Candidate, controlling: bool) -> Result<()> {
    let remote_port = if controlling { 9001 } else { 9000 };
    let uri = format!("http://127.0.0.1:{}/remoteCandidate", remote_port);
    let body = candidate.marshal();

    let stream = TcpStream::connect(format!("127.0.0.1:{}", remote_port)).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake failed")?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(hyper::header::HOST, format!("127.0.0.1:{}", remote_port))
        .body(body)
        .context("Failed to build credentials request")?;

    sender.send_request(req).await?;
    Ok(())
}

async fn attempt_health_check(uri: &str) -> Result<()> {
    // Parse the URI for both connection and request
    let uri = Uri::from_str(uri).context("Failed to parse health check URI")?;
    let host = uri.host().context("URI missing host")?;
    let port = uri.port_u16().context("URI missing port")?;
    let addr = format!("{}:{}", host, port);

    // Connect to the server
    let stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to remote server")?;

    let io = TokioIo::new(stream);

    // Create HTTP client connection
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake failed")?;

    // Spawn connection task
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    // Build and send request
    let req = Request::builder()
        .uri(uri.path())
        .header(hyper::header::HOST, format!("{}:{}", host, port))
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

fn initialize_ice_agent() -> Result<Agent> {
    Agent::new(Arc::new(AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    }))
    .context("Failed to initialize ICE agent")
}

async fn initialize_udp_socket(controlling: bool) -> Result<UdpSocket> {
    let port = if controlling { 4000 } else { 4001 };
    println!("Binding UDP socket on port {}", port);
    UdpSocket::bind(("0.0.0.0", port))
        .await
        .context("Failed to bind UDP socket")
}

fn determine_http_addr(controlling: bool) -> Result<SocketAddr> {
    let port = if controlling { 9000 } else { 9001 };
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging if debug is enabled
    if cli.debug {
        let log_level =
            log::LevelFilter::from_str(&cli.log_level).unwrap_or(log::LevelFilter::Info);
        env_logger::Builder::new().filter(None, log_level).init();
    }

    // Create and run application
    let app = App::new(&cli).await?;
    app.run().await?;

    Ok(())
}
