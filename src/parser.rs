use crate::capture::PacketObj;
use crate::dns_utils::{LogRecord, DnsFlow};
use crossbeam_channel::Receiver;
use etherparse::{PacketHeaders, IpHeader, TransportHeader, VlanHeader};
use dns_parser::{Packet as DnsPacket, RData, ResponseCode}; 
use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use log::info;
use std::thread;

type ContextMap = DashMap<String, (DnsFlow, SystemTime)>;

struct CacheState {
    record: LogRecord,
    last_seen: SystemTime,
    last_printed: SystemTime,
    printed_count: u64,
}

type OutputCache = DashMap<String, CacheState>;

pub fn run_parser(rx: Receiver<PacketObj>, cache_time: u64, print_time: u64, check_interval: u64) {
    let context: ContextMap = DashMap::new();
    let output_cache: std::sync::Arc<OutputCache> = std::sync::Arc::new(DashMap::new());

    let cache_ref = output_cache.clone();
    
    thread::spawn(move || {
        cleanup_loop(cache_ref, Duration::from_secs(cache_time), Duration::from_secs(print_time), Duration::from_secs(check_interval));
    });

    info!("Parser thread started (Cache: {}s, Print: {}s, Check: {}s)", cache_time, print_time, check_interval);

    while let Ok(pkt) = rx.recv() {
        parse_packet(&pkt, &context, &output_cache);
    }
}

fn to_iso(ts: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = ts.into();
    datetime.to_rfc3339()
}

fn cleanup_loop(cache: std::sync::Arc<OutputCache>, expiration: Duration, print_interval: Duration, check_interval: Duration) {
    loop {
        thread::sleep(check_interval);
        let mut keys_to_remove = Vec::new();
        let now = SystemTime::now();

        for mut r in cache.iter_mut() {
            let (key, state) = r.pair_mut();
            
            let age = now.duration_since(state.last_seen).unwrap_or(Duration::ZERO);
            if age > expiration {
                let delta = state.record.count - state.printed_count;
                if delta > 0 {
                    state.record.count = delta; 
                    state.record.ts = chrono::Utc::now().to_rfc3339();
                    println!("{}", serde_json::to_string(&state.record).unwrap());
                }
                keys_to_remove.push(key.clone());
                continue;
            }

            let time_since_print = now.duration_since(state.last_printed).unwrap_or(Duration::ZERO);
            if time_since_print > print_interval {
                let delta = state.record.count - state.printed_count;
                if delta > 0 {
                    let mut print_rec = state.record.clone();
                    print_rec.count = delta;
                    print_rec.ts = chrono::Utc::now().to_rfc3339();
                    println!("{}", serde_json::to_string(&print_rec).unwrap());

                    state.printed_count = state.record.count;
                    state.last_printed = now;
                }
            }
        }

        for k in keys_to_remove {
            cache.remove(&k);
        }
    }
}

fn parse_packet(pkt: &PacketObj, ctx: &ContextMap, cache: &DashMap<String, CacheState>) {
    let headers = match PacketHeaders::from_ethernet_slice(&pkt.data) {
        Ok(h) => h,
        Err(_) => return, 
    };

    let vlan_id = match headers.vlan {
        Some(VlanHeader::Single(h)) => h.vlan_identifier,
        Some(VlanHeader::Double(h)) => h.outer.vlan_identifier,
        None => 0,
    };

    let (src_ip, dst_ip) = match headers.ip {
        Some(IpHeader::Version4(h, _)) => (h.source.map(|x| x.to_string()).join("."), h.destination.map(|x| x.to_string()).join(".")),
        Some(IpHeader::Version6(h, _)) => (h.source.map(|x| x.to_string()).join(":"), h.destination.map(|x| x.to_string()).join(":")),
        _ => return,
    };

    let (src_port, dst_port, proto) = match headers.transport {
        Some(TransportHeader::Udp(u)) => (u.source_port, u.destination_port, 17),
        Some(TransportHeader::Tcp(t)) => (t.source_port, t.destination_port, 6),
        _ => return, 
    };

    let payload = headers.payload;
    if payload.is_empty() { return; }

    let dns = match DnsPacket::parse(payload) {
        Ok(d) => d,
        Err(_) => return, 
    };

    let tx_id = dns.header.id;
    
    if dns.header.query {
        let key = format!("{}:{}:{}:{}", tx_id, proto, src_ip, src_port);
        let flow = DnsFlow {
            src_ip: src_ip.clone(), dst_ip: dst_ip, src_port: src_port as u16, dst_port: dst_port as u16, proto, vlan: vlan_id, tx_id,
            query_name: String::new(), query_type: String::new(),
        };

        if let Some(q) = dns.questions.first() {
            let mut stored_flow = flow.clone();
            stored_flow.query_name = q.qname.to_string();
            stored_flow.query_type = format!("{:?}", q.qtype);
            ctx.insert(key, (stored_flow, pkt.ts));
        }

    } else {
        let key = format!("{}:{}:{}:{}", tx_id, proto, dst_ip, dst_port);
        
        if let Some((_, (flow, start_ts))) = ctx.remove(&key) {
            let latency = pkt.ts.duration_since(start_ts).unwrap_or_default().as_secs_f64();
            
            let mut answers: Vec<String> = dns.answers.iter()
                .map(|a| match &a.data {
                    RData::A(record) => record.0.to_string(),
                    RData::AAAA(record) => record.0.to_string(),
                    RData::CNAME(name) => name.to_string(),
                    RData::NS(name) => name.to_string(),
                    RData::PTR(name) => name.to_string(),
                    RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
                    RData::SOA(soa) => format!("{} {} {}", soa.primary_ns, soa.mailbox, soa.serial),
                    RData::TXT(txt) => {
                        txt.iter()
                           .map(|part| String::from_utf8_lossy(part).into_owned())
                           .collect::<Vec<String>>()
                           .join("")
                    },
                    _ => format!("{:?}", a.data),
                })
                .collect();
            
            answers.sort();

            let rc = match dns.header.response_code {
                ResponseCode::NoError => "NOERROR".to_string(),
                ResponseCode::NameError => "NXDOMAIN".to_string(),
                ResponseCode::FormatError => "FORMERR".to_string(),
                ResponseCode::ServerFailure => "SERVFAIL".to_string(),
                ResponseCode::NotImplemented => "NOTIMP".to_string(),
                ResponseCode::Refused => "REFUSED".to_string(),
                _ => format!("{:?}", dns.header.response_code).to_uppercase(),
            };

            let atype = dns.answers.last().map(|a| format!("{:?}", a.data)).unwrap_or_default();
            let mut clean_atype = atype.split('(').next().unwrap_or(&atype).to_string();
            
            if clean_atype.is_empty() {
                clean_atype = flow.query_type.clone();
            }

            let record = LogRecord {
                query: flow.query_name.clone(),
                qtype: flow.query_type.clone(),
                answer: answers.clone(),
                atype: clean_atype.clone(),
                rc: rc.clone(),
                ttl: dns.answers.first().map(|a| a.ttl).unwrap_or(0),
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                proto: flow.proto,
                vlan: flow.vlan,
                qid: flow.tx_id,
                latency,
                fts: to_iso(pkt.ts),
                lts: to_iso(pkt.ts),
                ts: chrono::Utc::now().to_rfc3339(),
                count: 1, 
            };

            let cache_key = if rc != "NOERROR" {
                 format!("{}:{}:{}", record.query, record.qtype, rc)
            } else {
                 let answer_key = answers.join(",");
                 format!("{}:{}:{}", record.query, clean_atype, answer_key)
            };

            if let Some(mut entry) = cache.get_mut(&cache_key) {
                let state = entry.value_mut();
                state.record.count += 1;
                state.record.lts = to_iso(pkt.ts);
                state.record.src_ip = record.src_ip;
                state.record.src_port = record.src_port;
                state.record.dst_ip = record.dst_ip;
                state.record.dst_port = record.dst_port;
                state.record.proto = record.proto;
                state.record.vlan = record.vlan;
                state.record.qid = record.qid;
                state.record.latency = record.latency;
                
                if record.ttl > state.record.ttl {
                    state.record.ttl = record.ttl;
                }
                state.last_seen = SystemTime::now();
            } else {
                println!("{}", serde_json::to_string(&record).unwrap());
                cache.insert(cache_key, CacheState {
                    record,
                    last_seen: SystemTime::now(),
                    last_printed: SystemTime::now(),
                    printed_count: 1,
                });
            }
        }
    }
}
