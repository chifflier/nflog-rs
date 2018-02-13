//!  Netfilter NFLOG high-level bindings
//!
//! libnetfilter_log is a userspace library providing interface to packets that
//! have been logged by the kernel packet filter. It is is part of a system that
//! deprecates the old syslog/dmesg based packet logging.
//!
//! libnetfilter_log homepage is: [http://netfilter.org/projects/libnetfilter_log/](http://netfilter.org/projects/libnetfilter_log/)
//!
//! **Using NFLOG requires root privileges, or the `CAP_NET_ADMIN` capability**
//!
//! The code is available on [Github](https://github.com/chifflier/nflog-rs)
//!
//! # Example
//!
//! ```rust,no_run
//! extern crate libc;
//! extern crate nflog;
//! use std::fmt::Write;
//!
//! fn callback(msg: nflog::Message) {
//!     println!(" -> msg: {}", msg);
//!     // this will send an error if there is no uid (for ex. incoming packets)
//!     println!(" -> uid: {}, gid: {}", msg.get_uid().unwrap(), msg.get_gid().unwrap());
//!     println!(" -> prefix: {}", msg.get_prefix().unwrap());
//!     println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));
//!
//!     let payload_data = msg.get_payload();
//!     let mut s = String::new();
//!     for &byte in payload_data {
//!         write!(&mut s, "{:X} ", byte).unwrap();
//!     }
//!     println!("{}", s);
//!
//!     println!("XML\n{}", msg.as_xml_str(&[nflog::XMLFormatFlags::XmlAll]).unwrap());
//!
//! }
//!
//! fn main() {
//!     let mut queue = nflog::Queue::open().unwrap();
//!
//!     queue.bind(libc::AF_INET).unwrap();
//!
//!     let mut group = queue.bind_group(0).unwrap();
//!
//!     group.set_mode(nflog::CopyMode::CopyPacket, 0xffff);
//!     group.set_flags(nflog::CfgFlags::CfgFlagsSeq);
//!
//!     group.set_callback(callback);
//!     queue.run_loop();
//!
//! }
//! ```


extern crate libc;

use std::panic;
use std::ptr;
use std::io;
use std::marker::PhantomData;

pub use hwaddr::*;
mod hwaddr;

pub use message::*;
mod message;

type NflogHandle = *const libc::c_void;
type NflogGroupHandle = *const libc::c_void;

/// Prototype for the callback function, triggered when a packet is received
type LogCallback = Fn(Message) + Send + Sync + 'static;

type NflogCCallback = Option<extern "C" fn (*const libc::c_void, *const libc::c_void, *const libc::c_void, *const libc::c_void) -> i32>;

#[link(name = "netfilter_log")]
extern {
    // library setup
    fn nflog_open() -> NflogHandle;
    fn nflog_close(qh: NflogHandle);
    fn nflog_bind_pf (qh: NflogHandle, pf: libc::c_int) -> libc::c_int;
    fn nflog_unbind_pf (qh: NflogHandle, pf: libc::c_int) -> libc::c_int;

    // group handling
    fn nflog_fd (h: NflogHandle) -> libc::c_int;
    fn nflog_bind_group (qh: NflogHandle, num: u16) -> NflogGroupHandle;
    fn nflog_unbind_group (gh: NflogGroupHandle) -> libc::c_int;
    fn nflog_set_mode (gh: NflogGroupHandle, mode: u8, range: u32) -> libc::c_int;
    fn nflog_set_timeout (gh: NflogGroupHandle, timeout: u32) -> libc::c_int;
    fn nflog_set_qthresh (gh: NflogGroupHandle, qthresh: u32) -> libc::c_int;
    fn nflog_set_nlbufsiz (gh: NflogGroupHandle, nlbufsiz: u32) -> libc::c_int;
    fn nflog_set_flags (gh: NflogGroupHandle, flags: u16) -> libc::c_int;

    // callback-related functions
    fn nflog_callback_register(gh: NflogGroupHandle, cb: NflogCCallback, data: *mut libc::c_void);
    fn nflog_handle_packet(qh: NflogHandle, buf: *mut libc::c_void, rc: libc::c_int) -> libc::c_int;
}




/// Copy modes
pub enum CopyMode {
    /// Do not copy packet contents nor metadata
    CopyNone,
    /// Copy only packet metadata, not payload
    CopyMeta,
    /// Copy packet metadata and not payload
    CopyPacket,
}
const NFULNL_COPY_NONE : u8   = 0x00;
const NFULNL_COPY_META : u8   = 0x01;
const NFULNL_COPY_PACKET : u8 = 0x02;

/// Configuration Flags
pub enum CfgFlags {
    CfgFlagsSeq,
    CfgFlagsSeqGlobal,
}
const NFULNL_CFG_F_SEQ : u16         = 0x0001;
const NFULNL_CFG_F_SEQ_GLOBAL : u16  = 0x0001;


pub struct Group<'a> {
    handle: NflogGroupHandle,
    callback: Option<Box<Box<LogCallback>>>,
    queue_lifetime: PhantomData<&'a Queue>,
}

impl<'a> Group<'a> {
    fn new(handle: NflogGroupHandle) -> Group<'a> {
        debug_assert!(!handle.is_null());
        Group {
            handle: handle,
            callback: None,
            queue_lifetime: PhantomData,
        }
    }

    /// Set the amount of packet data that nflog copies to userspace
    ///
    /// Arguments:
    ///
    /// * `mode` - The part of the packet that we are interested in
    /// * `range` - Size of the packet that we want to get
    ///
    /// `mode` can be one of:
    ///
    /// * `NFULNL_COPY_NONE` - do not copy any data
    /// * `NFULNL_COPY_META` - copy only packet metadata
    /// * `NFULNL_COPY_PACKET` - copy entire packet
    pub fn set_mode(&self, mode: CopyMode, range: u32) {
        debug_assert!(!self.handle.is_null());
        let c_mode = match mode {
            CopyMode::CopyNone => NFULNL_COPY_NONE,
            CopyMode::CopyMeta => NFULNL_COPY_META,
            CopyMode::CopyPacket => NFULNL_COPY_PACKET,
        };
        unsafe { nflog_set_mode(self.handle, c_mode, range); }
    }

    /// Sets the maximum time to push log buffer for this group
    ///
    /// Arguments:
    ///
    /// * `timeout` - Time to wait until the log buffer is pushed to userspace
    ///
    /// This function allows to set the maximum time that nflog waits until it
    /// pushes the log buffer to userspace if no new logged packets have occured.
    ///
    /// Basically, nflog implements a buffer to reduce the computational cost of
    /// delivering the log message to userspace.
    pub fn set_timeout(&self, timeout: u32) {
        assert!(!self.handle.is_null());
        unsafe { nflog_set_timeout(self.handle, timeout); }
    }

    /// Sets the maximum amount of logs in buffer for this group
    ///
    /// Arguments:
    ///
    /// * `qthresh` - Maximum number of log entries
    ///
    /// This function determines the maximum number of log entries in the
    /// buffer until it is pushed to userspace.
    pub fn set_qthresh(&self, qthresh: u32) {
        assert!(!self.handle.is_null());
        unsafe { nflog_set_qthresh(self.handle, qthresh); }
    }

    /// Sets the size of the nflog buffer for this group
    ///
    /// Arguments:
    ///
    /// * `nlbufsiz` - Size of the nflog buffer
    ///
    /// This function sets the size (in bytes) of the buffer that is used to
    /// stack log messages in nflog.
    pub fn set_nlbufsiz(&self, nlbufsiz: u32) {
        assert!(!self.handle.is_null());
        unsafe { nflog_set_nlbufsiz(self.handle, nlbufsiz); }
    }

    /// Sets the nflog flags for this group
    ///
    /// Arguments:
    ///
    /// * `flags` - Flags that you want to set
    ///
    /// There are two existing flags:
    ///
    /// * `NFULNL_CFG_F_SEQ`: This enables local nflog sequence numbering.
    /// * `NFULNL_CFG_F_SEQ_GLOBAL`: This enables global nflog sequence numbering.
    pub fn set_flags(&self, flags: CfgFlags) {
        assert!(!self.handle.is_null());
        let c_flags : u16 = match flags {
            CfgFlags::CfgFlagsSeq => NFULNL_CFG_F_SEQ,
            CfgFlags::CfgFlagsSeqGlobal => NFULNL_CFG_F_SEQ_GLOBAL,
        };
        unsafe { nflog_set_flags(self.handle, c_flags); }
    }


    /// Registers the callback triggered when a packet is received
    pub fn set_callback<F: Fn(Message) + Send + Sync + 'static>(&mut self, f: F) {
        self._set_callback(Box::new(f))
    }

    fn _set_callback(&mut self, f: Box<LogCallback>) {
        assert!(!self.handle.is_null());
        // Double box, so the value is a single pointer, not 2 pointers
        let cb_box = Box::new(f);
        unsafe { nflog_callback_register(self.handle, Some(real_callback), &*cb_box as *const Box<_> as *mut libc::c_void); };
        self.callback = Some(cb_box);
    }

    pub fn clear_callback(&mut self) {
        assert!(!self.handle.is_null());
        unsafe { nflog_callback_register(self.handle, None, ptr::null_mut()); };
        self.callback = None;
    }

}

impl<'a> Drop for Group<'a> {
    fn drop(&mut self) {
        unsafe { nflog_unbind_group(self.handle); }
    }
}

/// Opaque struct `Queue`: abstracts an NFLOG queue
pub struct Queue {
    handle: NflogHandle,
}


impl Queue {
    /// Opens a NFLOG Queue
    ///
    /// This function obtains a netfilter log connection handle.
    /// This handle will be automatically closed when the `Queue` is dropped
    /// A new netlink connection is obtained internally
    /// and associated with the log connection handle returned.
    pub fn open() -> io::Result<Queue> {
        let handle = unsafe { nflog_open() };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Queue {
            handle: handle,
        })
    }

    /// Bind a nflog handler to a given protocol family
    ///
    /// Binds the given log connection handle to process packets belonging to
    /// the given protocol family (ie. `PF_INET`, `PF_INET6`, etc).
    ///
    /// Arguments
    ///
    /// * `protocol_family` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn bind(&self, protocol_family: libc::c_int) -> io::Result<()> {
        debug_assert!(!self.handle.is_null());

        let result = unsafe { nflog_bind_pf(self.handle, protocol_family) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Unbinds the nflog handler from a protocol family
    ///
    /// Unbinds the given nflog handle from processing packets belonging to the
    /// given protocol family.
    ///
    /// Arguments
    ///
    /// * `protocol_family` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn unbind(&self, protocol_family: libc::c_int) -> io::Result<()> {
        debug_assert!(!self.handle.is_null());
        let result = unsafe { nflog_unbind_pf(self.handle, protocol_family) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Returns the C file descriptor associated with the nflog handler
    ///
    /// This function returns a file descriptor that can be used for
    /// communication over the netlink connection associated with the given log
    /// connection handle.
    pub fn fd(&self) -> i32 {
        debug_assert!(!self.handle.is_null());
        unsafe { nflog_fd(self.handle) }
    }

    ///  Binds a new handle to a specific group number.
    ///
    /// Arguments:
    ///
    /// * `num` - The number of the group to bind to
    pub fn bind_group(&self, num: u16) -> io::Result<Group> {
        debug_assert!(!self.handle.is_null());

        let group_handle = unsafe { nflog_bind_group(self.handle, num) };
        if group_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Group::new(group_handle))
    }

    /// Runs an infinite loop, waiting for packets and triggering the callback.
    pub fn run_loop(&self) -> ! {
        let fd = self.fd();
        let mut buf = vec![0; 0x10000];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        loop {
            let rc = unsafe { libc::recv(fd,buf_ptr,buf_len,0) };
            if rc < 0 { panic!("error in recv: {:?}", ::std::io::Error::last_os_error()); };

            let rv = unsafe { nflog_handle_packet(self.handle, buf_ptr, rc as libc::c_int) };
            if rv != 0 { eprintln!("error in nflog_handle_packet(): {}", rv); }; // not critical
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        debug_assert!(!self.handle.is_null());

        unsafe { nflog_close(self.handle) };
    }
}

extern "C" fn real_callback(_g: *const libc::c_void, _nfmsg: *const libc::c_void, nfad: *const libc::c_void, data: *const libc::c_void ) -> libc::c_int {
    // Let default hook print error
    let result = panic::catch_unwind(|| {
        let cb = data as *mut Box<for<'a> Fn(Message<'a>) + Send + Sync + 'static>;

        if cb.is_null() {
            panic!("No callback provided");
        }
        let cb = unsafe { &*cb };

        let msg = unsafe { Message::new(nfad) };
        cb(msg);
    });
    match result {
        Ok(_) => 0,
        Err(_) => 1,
    }
}



#[cfg(test)]
mod tests {

    extern crate libc;

    #[test]
    fn nflog_open() {
        let q = ::Queue::open().unwrap();

        let raw = q.handle as *const i32;
        assert!(!raw.is_null());
        println!("nfq_open: 0x{:x}", unsafe{*raw});
    }

    #[test]
    #[ignore]
    fn nflog_bind() {
        let q = ::Queue::open().unwrap();

        let raw = q.handle as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!q.handle.is_null());

        q.bind(libc::AF_INET).unwrap();
    }
}
