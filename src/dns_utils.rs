use serde::Serialize;

#[derive(Debug, Clone)]
pub struct DnsFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub vlan: u16,
    pub tx_id: u16,
    pub query_name: String,
    pub query_type: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct LogRecord {
    pub query: String,
    pub qtype: String,
    pub answer: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub atype: String,
    pub rc: String,
    pub ttl: u32,
    
    #[serde(rename = "cnt")]
    pub count: u64,
    
    pub fts: String,
    pub lts: String,
    #[serde(rename = "pts")]
    pub ts: String,
    
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub vlan: u16,
    pub qid: u16,

    #[serde(rename = "qtm")]
    pub latency: f64,
}
