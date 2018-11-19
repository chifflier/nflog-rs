#![allow(non_camel_case_types, non_upper_case_globals)]
//! libnfnetlink is the low-level library for netfilter related kernel/userspace
//! communication. It provides a generic messaging infrastructure for in-kernel
//! netfilter subsystems (such as nfnetlink_log, nfnetlink_queue,
//! nfnetlink_conntrack) and their respective users and/or management tools in
//! userspace.
//!
//! This library is not meant as a public API for application developers. It is
//! only used by other netfilter.org projects, such as libnetfilter_log,
//! libnetfilter_queue or libnetfilter_conntrack.
extern crate libc;

use libc::{iovec, msghdr, nlmsghdr, pid_t, sockaddr_nl};

include!("bindings.rs");
