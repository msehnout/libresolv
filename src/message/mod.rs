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

use defs::TYPE;
use rr::ResRec;

use std::convert::TryFrom;

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


#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub question: Vec<Question>,
    pub answer: Vec<ResRec>,
    pub authority: Vec<ResRec>,
    pub additional: Vec<ResRec>,
}

#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub qtype: TYPE,
    pub class: u16,
}

#[derive(Debug)]
pub struct QuestionBuilder {
    name: Option<String>,
    qtype: u16,
    class: u16,
}

impl Default for QuestionBuilder {
    fn default() -> Self {
        QuestionBuilder {
            name: None,
            qtype: 1,
            class: 1,
        }
    }
}

impl QuestionBuilder {
    pub fn no_name(qtype: u16, class: u16) -> QuestionBuilder {
        QuestionBuilder {
            name: None,
            qtype: qtype,
            class: class,
        }
    }

    pub fn set_name(mut self, name: String) -> QuestionBuilder {
        self.name = Some(name);
        self
    }

    pub fn set_qtype(mut self, qtype: u16) -> QuestionBuilder {
        self.qtype = qtype;
        self
    }

    pub fn set_class(mut self, class: u16) -> QuestionBuilder {
        self.class = class;
        self
    }

    pub fn finish(self) -> Question {
        Question {
            name: self.name.unwrap_or("".to_string()),
            // hmmm ... this should not happen, but in order to preserve
            // Builder patter, I'd like to return QuestionBuilder only
            qtype: TYPE::try_from(self.qtype).unwrap_or(TYPE::NULL),
            class: self.class,
        }
    }
}
