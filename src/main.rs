#[macro_use]
extern crate log;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use adblock::Engine;
use adblock::lists::ParseOptions;
use adblock::request::Request;
use clap::Parser;
use log::LevelFilter;
use simple_dns::{Packet, PacketFlag};
use tokio::io::AsyncBufReadExt;
use tokio::net::UdpSocket;
use udpproxi::UdpProxi;

async fn lookup_host(host: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(host).await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("failed to resolve {}", host)))
}

fn logger_init() -> io::Result<()> {
    use log4rs::append::console::ConsoleAppender;
    use log4rs::config::{Appender, Root};
    use log4rs::encode::pattern::PatternEncoder;

    let log_level = LevelFilter::from_str(
        std::env::var("DNSPROXI_LOG").as_deref().unwrap_or("INFO"),
    ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let pattern = if log_level == LevelFilter::Debug {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {f}:{L} - {m}{n}"
    } else {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}"
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(
            Root::builder()
                .appender("stdout")
                .build(log_level),
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    log4rs::init_config(config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(())
}

fn exec(args: Args) -> io::Result<()> {
    let bind = args.bind_addr;
    let rules_file = args.rules_file;
    let matched = args.matched.as_str();
    let not_matched = args.not_matched.as_str();

    logger_init()?;
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let mut rules = Vec::new();

        for path in rules_file {
            let file = tokio::fs::File::open(path).await?;
            let mut lines = tokio::io::BufReader::new(file).lines();

            loop {
                match lines.next_line().await? {
                    None => break,
                    Some(line) => rules.push(line)
                }
            }
        }

        let engine = Engine::from_rules(rules, ParseOptions::default());
        let socket = UdpSocket::bind(bind).await?;
        let socket = Arc::new(socket);

        info!("listening on {}", bind);

        let mut proxy = UdpProxi::new(socket.clone(), udpproxi::default_endpoint_creator);
        let mut buff = vec![0u8; 2048];

        loop {
            let (size, from) = match socket.recv_from(&mut buff).await {
                Ok(v) => v,
                Err(e) => {
                    error!("recv dns packet error: {:?}", e);
                    continue;
                },
            };

            let packet_buff = &buff[..size];

            let packet = match Packet::parse(packet_buff) {
                Ok(packet) => packet,
                Err(_) => continue
            };

            if packet.has_flags(PacketFlag::RESPONSE) {
                continue;
            }

            if packet.questions.len() == 1 {
                let qname = &packet.questions[0].qname;
                let req = Request::new(
                    &format!("http://{}", qname),
                    "",
                    "",
                ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let res = engine.check_network_request(&req);

                if res.matched {
                    let matched = lookup_host(matched).await?;

                    proxy.send_packet(
                        packet_buff,
                        from,
                        matched,
                    ).await?;

                    continue;
                }
            }

            let not_matched = lookup_host(not_matched).await?;

            proxy.send_packet(
                packet_buff,
                from,
                not_matched,
            ).await?;
        }
    })
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:53")]
    bind_addr: SocketAddr,

    /// blocking filter matched, example "8.8.8.8:53"
    #[arg(short, long)]
    matched: String,

    /// blocking filter not matched, example "223.5.5.5:53"
    #[arg(short, long)]
    not_matched: String,

    /// adblock rules
    #[arg(short, long)]
    rules_file: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    match exec(args) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}
