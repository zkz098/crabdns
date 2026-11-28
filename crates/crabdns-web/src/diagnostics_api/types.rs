use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DiagnosticStatus {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DiagnosticCategory {
    Listener,
    Upstream,
    Security,
    Storage,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DiagnosticItem {
    pub id: String,
    pub category: DiagnosticCategory,
    pub status: DiagnosticStatus,
    pub summary: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_tab: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct SystemDiagnosticsResponse {
    pub overall: DiagnosticStatus,
    #[ts(type = "number")]
    pub checked_at_ms: u64,
    pub listen_dns: String,
    pub items: Vec<DiagnosticItem>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct DomainTraceRequest {
    pub domain: String,
    #[serde(default = "default_trace_qtype")]
    pub qtype: String,
}

fn default_trace_qtype() -> String {
    "A".to_string()
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DomainTraceStep {
    pub stage: String,
    pub status: DiagnosticStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DomainTraceResponse {
    pub domain: String,
    pub qtype: String,
    pub rcode: String,
    pub outcome: String,
    pub elapsed_ms: f64,
    pub upstream: Option<String>,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
    pub split_dns_rule: Option<String>,
    pub answers: Vec<String>,
    pub steps: Vec<DomainTraceStep>,
}

pub(crate) fn build_dns_query_with_type(txid: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + domain.len());
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        if !label.is_empty() && label.len() <= 63 {
            buf.push(u8::try_from(label.len()).unwrap_or(0));
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0x00);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}
