mod capture;
mod parser;
mod dns_utils;
mod reasm;

use clap::Parser;
use log::{info, error};
use std::thread;
use crossbeam_channel::bounded;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short, long, default_value = "any")]
    interface: String,

    #[arg(short, long, default_value = "(port 53) or (ip[6:2] & 0x3fff != 0) or (ip6[6] = 0) or (ip6[6] = 43) or (ip6[6] = 44) or (ip6[6] = 60)")]
    bpf: String,

    #[arg(short, long, default_value_t = 1)]
    threads: usize,

    /// Seconds an idle answer stays cached before it is dropped. Default is 12 hours.
    #[arg(long, default_value_t = 43200)]
    cache_time: u64,

    /// Seconds before new sightings of an active answer are written. Default is 24 hours.
    #[arg(long, default_value_t = 86400)]
    print_time: u64,

    /// Seconds between cache scans. Default is 10 minutes.
    #[arg(long, default_value_t = 600)]
    check_interval: u64,

    /// Read this pcap instead of a live interface.
    #[arg(long)]
    pcap: Option<String>,

    /// Append JSON logs to this file. Omit it, or pass "-", to write stdout.
    #[arg(short = 'l', long)]
    logfile: Option<String>,
}

fn main() {
    env_logger::init();
    let config = Config::parse();

    info!("Starting PassiveDNS Rust on interface: {}", config.interface);

    let running = Arc::new(AtomicBool::new(true));
    let stop = running.clone();
    ctrlc::set_handler(move || {
        error!("Ctrl+C received, stopping.");
        stop.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let (packet_tx, packet_rx) = bounded(10_000);

    // Pass all timing configs to parser
    let parser_cache_time = config.cache_time;
    let parser_print_time = config.print_time;
    let parser_check_interval = config.check_interval;
    let log = match config.logfile.as_deref() {
        None | Some("-") => parser::LogOut::stdout(),
        Some(path) => match parser::LogOut::open(path) {
            Ok(log) => log,
            Err(e) => {
                eprintln!("[!] Cannot open logfile {path}: {e}");
                std::process::exit(1);
            }
        },
    };

    let parser_handle = thread::spawn(move || {
        parser::run_parser(packet_rx, log, parser_cache_time, parser_print_time, parser_check_interval);
    });

    let capture_config = config.clone();
    let capture_handle = thread::spawn(move || {
        if let Err(e) = capture::run_capture(capture_config.interface, capture_config.bpf, capture_config.pcap, packet_tx, running) {
            error!("Capture failed: {}", e);
        }
    });

    let _ = capture_handle.join();
    let _ = parser_handle.join();
}
