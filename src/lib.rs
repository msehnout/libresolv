#![feature(try_from)]

//! # A DNS library for Rust programming language
//!
//! The library provides essential data structures and functionality
//! for communication inside Domain Name System. List of currently
//! supported RFCs:
//!
//! 1. [RFC 1035: Domain Names - Implementation and specification - partially ](http://www.rfcreader.com/#rfc1035)

#[macro_use]
extern crate nom;

pub mod defs;
pub mod error;
pub mod message;
pub mod rr;
pub mod wire;
