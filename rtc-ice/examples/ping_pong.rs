use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as Body, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo; // Importing TokioIo
use lazy_static::lazy_static;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

type SenderType = Arc<Mutex<mpsc::Sender<String>>>;
type ReceiverType = Arc<Mutex<mpsc::Receiver<String>>>;

lazy_static! {
    static ref REMOTE_AUTH_CHANNEL: (SenderType, ReceiverType) = {
        let (tx, rx) = mpsc::channel::<String>(3);
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    };
    static ref REMOTE_CAND_CHANNEL: (SenderType, ReceiverType) = {
        let (tx, rx) = mpsc::channel::<String>(10);
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    };
}

async fn remote_handler(req: Request<Body>) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/remoteAuth") => {
            let full_body = match req.into_body().collect().await {
                Ok(b) => b,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .expect("Failed to build response"));
                }
            };

            let body_str = match from_utf8(&full_body.to_bytes()) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::new()))
                        .expect("Failed to build response"));
                }
            };

            let tx = REMOTE_AUTH_CHANNEL.0.lock().await;
            tx.send(body_str).await.unwrap_or_default();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .expect("Failed to build response"))
        }

        (&Method::POST, "/remoteCandidate") => {
            let full_body = match req.into_body().collect().await {
                Ok(b) => b,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .expect("Failed to build response"));
                }
            };

            let body_str = match from_utf8(&full_body.to_bytes()) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::new()))
                        .expect("Failed to build response"));
                }
            };

            let tx = REMOTE_CAND_CHANNEL.0.lock().await;
            tx.send(body_str).await.unwrap_or_default();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .expect("Failed to build response"))
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .expect("Failed to build response")),
    }
}

// Controlled Agent:
//      cargo run --color=always --package rtc-ice --example ping_pong
// Controlling Agent:
//      cargo run --color=always --package rtc-ice --example ping_pong -- --controlling

#[derive(Parser)]
#[command(name = "ICE Ping Pong")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of ICE", long_about = None)]
struct Cli {
    #[arg(short, long)]
    controlling: bool,

    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let (local_http_port, _) = if cli.controlling {
        (9000, 9001)
    } else {
        (9001, 9000)
    };

    let addr: SocketAddr = ([0, 0, 0, 0], local_http_port).into();
    println!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down HTTP server.");
        }
        res = async {
            loop {
                let (stream, _) = listener.accept().await?;
                let service = service_fn(remote_handler);

                // Wrap the TcpStream in TokioIo so hyper can use it
                let io = TokioIo::new(stream);

                tokio::spawn(async move {
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("Error serving connection: {}", e);
                    }
                });
            }

            #[allow(unreachable_code)]
            Ok::<(), Box<dyn std::error::Error>>(())
        } => {
            if let Err(e) = res {
                eprintln!("Server error: {}", e);
            }
        }
    }

    Ok(())
}
