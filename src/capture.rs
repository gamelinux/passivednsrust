use pcap::{Capture, Device};
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use log::info;

#[derive(Debug)]
pub struct PacketObj {
    pub ts: SystemTime,
    pub data: Vec<u8>,
}

fn packet_time(header: &pcap::PacketHeader) -> SystemTime {
    let sec = if header.ts.tv_sec < 0 { 0 } else { header.ts.tv_sec as u64 };
    let usec = if header.ts.tv_usec < 0 { 0 } else { header.ts.tv_usec as u32 };
    UNIX_EPOCH + Duration::new(sec, usec.saturating_mul(1000))
}

pub fn run_capture(
    interface: String,
    bpf: String,
    pcap_path: Option<String>,
    tx: Sender<PacketObj>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = pcap_path {
        let mut cap = Capture::from_file(path)?;
        if !bpf.is_empty() {
            cap.filter(&bpf, true)?;
        }
        info!("Reading pcap.");
        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    let obj = PacketObj {
                        ts: packet_time(&packet.header),
                        data: packet.data.to_vec(),
                    };
                    if tx.send(obj).is_err() {
                        break;
                    }
                },
                Err(pcap::Error::NoMorePackets) => break,
                Err(e) => {
                    eprintln!("PCAP Error: {}", e);
                    break;
                }
            }
        }
        info!("Pcap read finished.");
        return Ok(());
    }

    let device = if interface == "any" {
        Device::lookup()?.unwrap() 
    } else {
        Device::from(interface.as_str())
    };

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535) 
        .timeout(100) 
        .open()?;

    cap.filter(&bpf, true)?;

    info!("Capture loop started.");

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let obj = PacketObj {
                    ts: SystemTime::now(),
                    data: packet.data.to_vec(),
                };
                if tx.send(obj).is_err() {
                    break;
                }
            },
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => eprintln!("PCAP Error: {}", e),
        }
    }
    
    info!("Capture loop stopping...");
    Ok(())
}
