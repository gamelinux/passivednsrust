use serde::{Serialize, Serializer};

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

fn ser_qtm<S>(v: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let text = format!("{:.6}", v);
    let n: serde_json::Number = text.parse().map_err(serde::ser::Error::custom)?;
    n.serialize(serializer)
}

#[derive(Serialize, Clone, Debug)]
pub struct LogRecord {
    pub query: String,
    pub qtype: String,
    pub answer: Vec<String>,
    pub atype: String,
    pub qid: u16,
    pub rc: String,
    pub ttl: u32,

    #[serde(rename = "cnt")]
    pub count: u64,

    pub fts: String,
    pub lts: String,
    #[serde(rename = "pts")]
    pub ts: String,

    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: u8,
    pub vlan: u16,

    #[serde(rename = "qtm", serialize_with = "ser_qtm")]
    pub latency: f64,
}
