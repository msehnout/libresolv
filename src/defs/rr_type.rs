//! This file specify RR type values.
//! NOTE: the values were automatically generated with gen_enum.py script

use std::convert::TryFrom;

use error::Error;

/// RR type as defined in RFC 1035
#[derive(Copy,Clone,Debug,PartialEq)]
pub enum TYPE {
    /// a host address
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail destination (Obsolete - use MX)
    MD = 3,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
}

impl TryFrom<u16> for TYPE {
    // TODO: use Error module
    type Err = Error;
    fn try_from(num: u16) -> Result<Self, Self::Err> {
        match num {
            1 => Ok(TYPE::A),
            2 => Ok(TYPE::NS),
            3 => Ok(TYPE::MD),
            4 => Ok(TYPE::MF),
            5 => Ok(TYPE::CNAME),
            6 => Ok(TYPE::SOA),
            7 => Ok(TYPE::MB),
            8 => Ok(TYPE::MG),
            9 => Ok(TYPE::MR),
            10 => Ok(TYPE::NULL),
            11 => Ok(TYPE::WKS),
            12 => Ok(TYPE::PTR),
            13 => Ok(TYPE::HINFO),
            14 => Ok(TYPE::MINFO),
            15 => Ok(TYPE::MX),
            16 => Ok(TYPE::TXT),
            _ => Err(Error::MalformedPacket),
        }
    }
}
