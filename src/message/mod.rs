//! Queries, responses, message header etc.
//!
//! ## RFC states:
//! ```txt
//! All communications inside of the domain protocol are carried in a single
//! format called a message.  The top level format of message is divided
//! into 5 sections (some of which are empty in certain cases) shown below:
//! 
//!     +---------------------+
//!     |        Header       |
//!     +---------------------+
//!     |       Question      | the question for the name server
//!     +---------------------+
//!     |        Answer       | RRs answering the question
//!     +---------------------+
//!     |      Authority      | RRs pointing toward an authority
//!     +---------------------+
//!     |      Additional     | RRs holding additional information
//!     +---------------------+
//! ```


/// Message header
#[derive(Debug)]
pub struct Header {
    /// Transaction ID used to match replies to queries
    pub id: u16,
    /// Query (0, false), Respense (1, true)
    pub response: bool,
    /// Kind of query
    /// * 0 - standard
    /// * 1 - inverse
    /// * 2 - server status
    pub opcode: u8,
    /// Authoritative answer (response comes from authority for
    /// the domain name)
    pub aa: bool,
    /// Truncation - message was truncated due to insufficient
    /// channel capabilities
    pub tc: bool,
    /// Recursion desired
    pub rd: bool,
    /// Recursion available
    pub ra: bool,
    pub z: u8,
    /// Response code
    pub rcode: u8,
    /// Number of queries
    pub qdcount: u16,
    /// Number of answers
    pub ancount: u16,
    /// Number of authority records
    pub nscount: u16,
    /// Number of additional records
    pub arcount: u16,
}
