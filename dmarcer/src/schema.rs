//! DMARC RUA schema definition
//!
//! Initially generated with [xgen](https://github.com/xuri/xgen),
//! based on the [DMARC RUA XSD](https://dmarc.org/dmarc-xml/0.1/rua.xsd),
//! then manually edited to fix some issues.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The time range in UTC covered by messages in this report, specified in seconds since epoch.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct DateRangeType {
    pub begin: u32,
    pub end: u32,
}

/// Report generator metadata
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ReportMetadataType {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRangeType,
    pub error: Option<Vec<String>>,
}

/// Alignment mode (relaxed or strict) for DKIM and SPF.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlignmentType {
    R,
    S,
}

/// The policy actions specified by p and sp in the DMARC record.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DispositionType {
    None,
    Quarantine,
    Reject,
}

///  The DMARC policy that applied to the messages in this report.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PolicyPublishedType {
    pub domain: String,
    pub adkim: AlignmentType,
    pub aspf: AlignmentType,
    pub p: DispositionType,
    pub sp: DispositionType,
    pub pct: u8,
}

/// The DMARC-aligned authentication result.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DMARCResultType {
    Pass,
    Fail,
}

/// Reasons that may affect DMARC disposition or execution thereof.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOverrideType {
    /// Message was relayed via a known forwarder, or local heuristics identified the message
    /// as likely having been forwarded. There is no expectation that authentication would pass.
    Forwarded,

    /// Message was exempted from application of policy by the "pct" setting in the DMARC policy record.
    SampledOut,

    /// Message authentication failure was anticipated by other evidence linking
    /// the message to a locally-maintained list of known and trusted forwarders.
    TrustedForwarder,

    /// Local heuristics determined that the message arrived via a mailing list,
    /// and thus authentication of the original message was not expected to succeed.
    MailingList,

    /// The Mail Receiver's local policy exempted the message from
    /// being subjected to the Domain Owner's requested policy action.
    LocalPolicy,

    /// Some policy exception not covered by the other entries in this list occurred.
    /// Additional detail can be found in the PolicyOverrideReason's "comment" field.
    Other,
}

/// How do we allow report generators to include new classes of override reasons
/// if they want to be more specific than "other"?
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PolicyOverrideReason {
    #[serde(rename = "type")]
    pub type_attr: PolicyOverrideType,
    pub comment: Option<String>,
}

/// Taking into account everything else in the record, the results of applying DMARC.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PolicyEvaluatedType {
    pub disposition: DispositionType,
    pub dkim: DMARCResultType,
    pub spf: DMARCResultType,
    pub reason: Option<Vec<PolicyOverrideReason>>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct RowType {
    /// The connecting IP.
    pub source_ip: IpAddr,

    /// The number of matching messages.
    pub count: u32,

    /// The DMARC disposition applying to matching messages.
    pub policy_evaluated: Option<PolicyEvaluatedType>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct IdentifierType {
    /// The envelope recipient domain.
    pub envelope_to: Option<String>,

    /// The payload From domain.
    pub header_from: String,
}

/// DKIM verification result, according to RFC 5451 Section 2.4.1.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DKIMResultType {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct DKIMAuthResultType {
    ///  The d= parameter in the signature.
    pub domain: String,

    /// The "s=" parameter in the signature.
    pub selector: Option<String>,

    /// The DKIM verification result.
    pub result: DKIMResultType,

    /// Any extra information (e.g., from Authentication-Results).
    pub human_result: Option<String>,
}

/// SPF result
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SPFResultType {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    /// "TempError" commonly implemented as "unknown"
    TempError,
    /// "PermError" commonly implemented as "error"
    PermError,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SPFAuthResultType {
    /// The envelope From domain.
    pub domain: String,

    /// The SPF verification result.
    pub result: SPFResultType,
}

/// This element contains DKIM and SPF results, uninterpreted with respect to DMARC.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct AuthResultType {
    /// There may be no DKIM signatures, or multiple DKIM signatures.
    pub dkim: Option<Vec<DKIMAuthResultType>>,

    /// There will always be at least one SPF result.
    pub spf: Vec<SPFAuthResultType>,
}

/// This element contains all the authentication results used
/// to evaluate the DMARC disposition for the given set of messages.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct RecordType {
    pub row: RowType,
    pub identifiers: IdentifierType,
    pub auth_results: AuthResultType,
}

/// Parent
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Feedback {
    pub report_metadata: ReportMetadataType,
    pub policy_published: PolicyPublishedType,
    pub record: Vec<RecordType>,
}
