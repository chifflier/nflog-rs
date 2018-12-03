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
//!     println!(" -> msg: {:?}", msg);
//!     // this will send an error if there is no uid (for ex. incoming packets)
//!     println!(" -> uid: {}, gid: {}", msg.get_uid().unwrap(), msg.get_gid().unwrap());
//!     println!(" -> prefix: {}", msg.get_prefix().to_string_lossy());
//!     println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));
//!
//!     let payload_data = msg.get_payload();
//!     let mut s = String::new();
//!     for &byte in payload_data {
//!         write!(&mut s, "{:X} ", byte).unwrap();
//!     }
//!     println!("{}", s);
//!
//!     println!("XML\n{}", msg.as_xml_str(nflog::XMLFormat::default()).unwrap());
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
//!     group.set_mode(nflog::CopyMode::Packet, 0xffff);
//!     group.set_flags(nflog::Flags::Sequence);
//!
//!     group.set_callback(Box::new(callback));
//!     queue.run_loop();
//!
//! }
//! ```

extern crate libc;
extern crate nflog_sys;
#[macro_use]
extern crate bitflags;

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::os::unix::io::RawFd;
use std::panic;
use std::ptr::{self, NonNull};

mod hwaddr;
pub use hwaddr::HwAddr;

mod message;
pub use message::{Message, NflogError, XMLFormat};

pub type Callback = Box<Fn(Message) + 'static>;

use nflog_sys::*;

/// Prototype for the callback function, triggered when a packet is received

/// Copy modes
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum CopyMode {
    /// Do not copy packet contents nor metadata
    None = NFULNL_COPY_NONE,
    /// Copy only packet metadata, not payload
    Meta = NFULNL_COPY_META,
    /// Copy packet metadata and not payload
    Packet = NFULNL_COPY_PACKET,
}

impl Default for CopyMode {
    fn default() -> Self {
        CopyMode::Packet
    }
}

bitflags!{
    /// Configuration Flags
    pub struct Flags: u16 {
        const Sequence = NFULNL_CFG_F_SEQ;
        const GlobalSequence = NFULNL_CFG_F_SEQ_GLOBAL;
    }
}

pub struct Group<'a> {
    handle: NonNull<nflog_g_handle>,
    group: u16,
    callback: Option<Box<Callback>>,
    queue_lifetime: PhantomData<&'a Queue>,
}

impl<'a> fmt::Debug for Group<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Group")
            .field("num", &self.group)
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

impl<'a> Group<'a> {
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
    pub fn set_mode(&mut self, mode: CopyMode, range: u32) {
        let c_mode = mode as u8;
        unsafe {
            nflog_set_mode(self.handle.as_ptr(), c_mode, range);
        }
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
    pub fn set_timeout(&mut self, timeout: u32) {
        unsafe {
            nflog_set_timeout(self.handle.as_ptr(), timeout);
        }
    }

    /// Sets the maximum amount of logs in buffer for this group
    ///
    /// Arguments:
    ///
    /// * `qthresh` - Maximum number of log entries
    ///
    /// This function determines the maximum number of log entries in the
    /// buffer until it is pushed to userspace.
    pub fn set_qthresh(&mut self, qthresh: u32) {
        unsafe {
            nflog_set_qthresh(self.handle.as_ptr(), qthresh);
        }
    }

    /// Sets the size of the nflog buffer for this group
    ///
    /// Arguments:
    ///
    /// * `nlbufsiz` - Size of the nflog buffer
    ///
    /// This function sets the size (in bytes) of the buffer that is used to
    /// stack log messages in nflog.
    pub fn set_nlbufsiz(&mut self, nlbufsiz: u32) {
        unsafe {
            nflog_set_nlbufsiz(self.handle.as_ptr(), nlbufsiz);
        }
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
    pub fn set_flags(&mut self, flags: Flags) {
        unsafe {
            nflog_set_flags(self.handle.as_ptr(), flags.bits());
        }
    }

    /// Registers the callback triggered when a packet is received
    pub fn set_callback(&mut self, f: Callback) {
        // Double box, so the value is a single pointer, not 2 pointers
        let cb_box = Box::new(f);
        unsafe {
            nflog_callback_register(
                self.handle.as_ptr(),
                Some(real_callback),
                &*cb_box as *const Box<_> as *mut _,
            );
        };
        self.callback = Some(cb_box);
    }

    pub fn clear_callback(&mut self) {
        unsafe {
            nflog_callback_register(self.handle.as_ptr(), None, ptr::null_mut());
        };
        self.callback = None;
    }

    pub fn callback(&self) -> Option<&Callback> {
        self.callback.as_ref().map(|cb| &**cb)
    }
}

impl<'a> Drop for Group<'a> {
    fn drop(&mut self) {
        unsafe {
            nflog_unbind_group(self.handle.as_ptr());
        }
    }
}

/// Opaque struct `Queue`: abstracts an NFLOG queue
#[derive(Debug)]
pub struct Queue {
    handle: NonNull<nflog_handle>,
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
            handle: unsafe { NonNull::new_unchecked(handle) },
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
        let result = unsafe { nflog_bind_pf(self.handle.as_ptr(), protocol_family as u16) };
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
        let result = unsafe { nflog_unbind_pf(self.handle.as_ptr(), protocol_family as u16) };
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
    pub fn fd(&self) -> RawFd {
        unsafe { nflog_fd(self.handle.as_ptr()) }
    }

    ///  Binds a new handle to a specific group number.
    ///
    /// Arguments:
    ///
    /// * `num` - The number of the group to bind to
    pub fn bind_group(&self, num: u16) -> io::Result<Group> {
        let group_handle = unsafe { nflog_bind_group(self.handle.as_ptr(), num) };
        if group_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Group {
            handle: unsafe { NonNull::new_unchecked(group_handle) },
            group: num,
            callback: None,
            queue_lifetime: PhantomData,
        })
    }

    /// Runs an infinite loop, waiting for packets and triggering the callback.
    pub fn run_loop(&self) -> ! {
        let fd = self.fd();
        let mut buf = vec![0u8; 0x10000];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        loop {
            let rc = unsafe { libc::recv(fd, buf_ptr, buf_len, 0) };
            if rc < 0 {
                panic!("error in recv: {:?}", ::std::io::Error::last_os_error());
            };

            unsafe {
                nflog_handle_packet(
                    self.handle.as_ptr(),
                    buf_ptr as *mut libc::c_char,
                    rc as libc::c_int,
                )
            };
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe { nflog_close(self.handle.as_ptr()) };
    }
}

extern "C" fn real_callback(
    _gh: *mut nflog_g_handle,
    _nfmsg: *mut nfgenmsg,
    nfd: *mut nflog_data,
    data: *mut std::os::raw::c_void,
) -> libc::c_int {
    if data.is_null() {
        return 1;
    }
    // Let default hook print error
    let result = panic::catch_unwind(|| {
        let cb = data as *mut Box<for<'a> Fn(Message<'a>) + Send + Sync + 'static>;
        let cb = unsafe { &*cb };

        let msg = unsafe { Message::new(nfd) };
        cb(msg);
    });
    match result {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nflog_open() {
        let q = Queue::open().unwrap();

        let raw = q.handle;
        println!("nfq_open: {:p}", raw);
    }

    #[test]
    #[ignore]
    fn nflog_bind() {
        let q = Queue::open().unwrap();

        let raw = q.handle;
        println!("nfq_open: {:p}", raw);

        q.bind(libc::AF_INET).unwrap();
    }
}
