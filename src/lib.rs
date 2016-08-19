//!  Netfilter NFLOG high-level bindings
//!
//! libnetfilter_log is a userspace library providing interface to packets that
//! have been logged by the kernel packet filter. It is is part of a system that
//! deprecates the old syslog/dmesg based packet logging.
//!
//! libnetfilter_log homepage is: http://netfilter.org/projects/libnetfilter_log/
//!
//! **Using NFLOG requires root privileges, or the `CAP_NET_ADMIN` capability**
//!
//! The code is available on [Github](https://github.com/chifflier/nflog-rust)
//!
//! # Example
//!
//! ```rust,ignore
//! extern crate libc;
//! extern crate nflog;
//! use std::fmt::Write;
//!
//! fn callback(msg: &nflog::Message) {
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
//!     let mut q = nflog::Queue::new();
//!
//!     q.open();
//!
//!     let rc = q.bind(libc::AF_INET);
//!     assert!(rc == 0);
//!
//!     q.bind_group(0);
//!
//!     q.set_mode(nflog::CopyMode::CopyPacket, 0xffff);
//!     q.set_flags(nflog::CfgFlags::CfgFlagsSeq);
//!
//!     q.set_callback(callback);
//!     q.run_loop();
//!
//!     q.close();
//! }
//! ```


extern crate libc;

pub use hwaddr::*;
mod hwaddr;

type NflogHandle = *const libc::c_void;
type NflogGroupHandle = *const libc::c_void;

/// Prototype for the callback function, triggered when a packet is received
pub type NflogCallback = fn (&Message) -> ();

type NflogData = *const libc::c_void;
type NflogCCallback = extern "C" fn (*const libc::c_void, *const libc::c_void, *const libc::c_void, *const libc::c_void );

/// Hardware address
#[repr(C)]
struct NfMsgPacketHw {
    /// Hardware address length
    pub hw_addrlen : u16,
    /// Padding (should be ignored)
    pub _pad : u16,
    /// The hardware address
    pub hw_addr : [u8;8],
}

/// Metaheader wrapping a packet
#[repr(C)]
pub struct NfMsgPacketHdr {
    /// hw protocol (network order)
    pub hw_protocol : u16,
    /// Netfilter hook
    pub hook : u8,
    /// Padding (should be ignored)
    pub pad : u8,
}

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

    // message parsing functions
    fn nflog_get_msg_packet_hdr(nfad: NflogData) -> *const libc::c_void;
    fn nflog_get_hwtype (nfad: NflogData) -> u16;

    fn nflog_get_nfmark (nfad: NflogData) -> u32;
    fn nflog_get_timestamp (nfad: NflogData, tv: *mut libc::timeval) -> u32;
    fn nflog_get_indev (nfad: NflogData) -> u32;
    fn nflog_get_physindev (nfad: NflogData) -> u32;
    fn nflog_get_outdev (nfad: NflogData) -> u32;
    fn nflog_get_physoutdev (nfad: NflogData) -> u32;
    fn nflog_get_packet_hw (nfad: NflogData) -> *const NfMsgPacketHw;
    fn nflog_get_payload (nfad: NflogData, data: &*mut libc::c_void) -> libc::c_int;
    fn nflog_get_prefix (nfad: NflogData) -> *const libc::c_char;
    fn nflog_get_uid (nfad: NflogData, uid: *mut u32) -> libc::c_int;
    fn nflog_get_gid (nfad: NflogData, uid: *mut u32) -> libc::c_int;
    fn nflog_get_seq (nfad: NflogData, uid: *mut u32) -> libc::c_int;
    fn nflog_get_seq_global (nfad: NflogData, uid: *mut u32) -> libc::c_int;

    // printing functions
    fn nflog_snprintf_xml (buf: *mut u8, rem: libc::size_t, tb: NflogData, flags: libc::c_uint) -> libc::c_int;

    // callback-related functions
    fn nflog_callback_register(gh: NflogGroupHandle, cb: NflogCCallback, data: *mut libc::c_void);
    fn nflog_handle_packet(qh: NflogHandle, buf: *mut libc::c_void, rc: libc::c_int) -> libc::c_int;
}


#[derive(Debug)]
pub enum NflogError {
    NoSuchAttribute,
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

/// XML formatting flags
pub enum XMLFormatFlags {
    XmlPrefix,
    XmlHw,
    XmlMark,
    XmlDev,
    XmlPhysDev,
    XmlPayload,
    XmlTime,
    XmlAll,
}
const NFLOG_XML_PREFIX  : u32  = (1 << 0);
const NFLOG_XML_HW      : u32  = (1 << 1);
const NFLOG_XML_MARK    : u32  = (1 << 2);
const NFLOG_XML_DEV     : u32  = (1 << 3);
const NFLOG_XML_PHYSDEV : u32  = (1 << 4);
const NFLOG_XML_PAYLOAD : u32  = (1 << 5);
const NFLOG_XML_TIME    : u32  = (1 << 6);
const NFLOG_XML_ALL     : u32  = (!0u32);


/// Opaque struct `Queue`: abstracts an NFLOG queue
pub struct Queue {
    qh  : NflogHandle,
    gh  : NflogGroupHandle,
    cb : Option<NflogCallback>,
}

/// Opaque struct `Message`: abstracts NFLOG data representing a packet data and metadata
pub struct Message {
    nfad : NflogData,
}


impl Queue {
    /// Creates a new, uninitialized, `Queue`.
    pub fn new() -> Queue {
        return Queue {
            qh : std::ptr::null_mut(),
            gh : std::ptr::null_mut(),
            cb: None,
        };
    }

    /// Opens a NFLOG handler
    ///
    /// This function obtains a netfilter log connection handle. When you are
    /// finished with the handle returned by this function, you should destroy it
    /// by calling `close()`.
    /// A new netlink connection is obtained internally
    /// and associated with the log connection handle returned.
    pub fn open(&mut self) {
        self.qh = unsafe { nflog_open() };
    }

    /// Closes a NFLOG handler
    ///
    /// This function closes the nflog handler and free associated resources.
    pub fn close(&mut self) {
        unsafe { nflog_close(self.qh) };
        self.qh = std::ptr::null_mut();
    }

    /// Bind a nflog handler to a given protocol family
    ///
    /// Binds the given log connection handle to process packets belonging to
    /// the given protocol family (ie. `PF_INET`, `PF_INET6`, etc).
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn bind(&self, pf: libc::c_int) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nflog_bind_pf(self.qh,pf) };
    }

    /// Unbinds the nflog handler from a protocol family
    ///
    /// Unbinds the given nflog handle from processing packets belonging to the
    /// given protocol family.
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn unbind(&self, pf: libc::c_int) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nflog_unbind_pf(self.qh,pf) }
    }

    /// Returns the C file descriptor associated with the nflog handler
    ///
    /// This function returns a file descriptor that can be used for
    /// communication over the netlink connection associated with the given log
    /// connection handle.
    pub fn fd(&self) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nflog_fd(self.qh) }
    }

    ///  Binds a new handle to a specific group number.
    ///
    /// Arguments:
    ///
    /// * `num` - The number of the group to bind to
    pub fn bind_group(&mut self, num: u16) {
        assert!(!self.qh.is_null());
        self.gh = unsafe { nflog_bind_group(self.qh,num) }
    }

    /// Unbinds a group handle
    ///
    /// Arguments:
    ///
    /// * `num` - The number of the group to unbind to
    pub fn unbind_group(&mut self) {
        assert!(!self.gh.is_null());
        unsafe { nflog_unbind_group(self.gh); }
        self.gh = std::ptr::null_mut();
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
        assert!(!self.gh.is_null());
        let c_mode = match mode {
            CopyMode::CopyNone => NFULNL_COPY_NONE,
            CopyMode::CopyMeta => NFULNL_COPY_META,
            CopyMode::CopyPacket => NFULNL_COPY_PACKET,
        };
        unsafe { nflog_set_mode(self.gh, c_mode, range); }
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
        assert!(!self.gh.is_null());
        unsafe { nflog_set_timeout(self.gh, timeout); }
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
        assert!(!self.gh.is_null());
        unsafe { nflog_set_qthresh(self.gh, qthresh); }
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
        assert!(!self.gh.is_null());
        unsafe { nflog_set_nlbufsiz(self.gh, nlbufsiz); }
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
        assert!(!self.gh.is_null());
        let c_flags : u16 = match flags {
            CfgFlags::CfgFlagsSeq => NFULNL_CFG_F_SEQ,
            CfgFlags::CfgFlagsSeqGlobal => NFULNL_CFG_F_SEQ_GLOBAL,
        };
        unsafe { nflog_set_flags(self.gh, c_flags); }
    }


    /// Registers the callback triggered when a packet is received
    pub fn set_callback(&mut self, cb: NflogCallback) {
        self.cb = Some(cb);
        let self_ptr = unsafe { std::mem::transmute(&*self) };
        unsafe { nflog_callback_register(self.gh, real_callback, self_ptr); };
    }

    /// Runs an infinite loop, waiting for packets and triggering the callback.
    pub fn run_loop(&self) {
        assert!(!self.gh.is_null());

        let fd = self.fd();
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        loop {
            let rc = unsafe { libc::recv(fd,buf_ptr,buf_len,0) };
            if rc < 0 { panic!("error in recv()"); };

            let rv = unsafe { nflog_handle_packet(self.qh, buf_ptr, rc as libc::c_int) };
            if rv < 0 { println!("error in nflog_handle_packet()"); }; // not critical
        }
    }
}

#[doc(hidden)]
#[no_mangle]
pub extern "C" fn real_callback(_g: *const libc::c_void, _nfmsg: *const libc::c_void, nfad: *const libc::c_void, data: *const libc::c_void ) {
    let raw : *mut Queue = unsafe { std::mem::transmute(data) };

    let ref mut q = unsafe { &*raw };
    let mut msg = Message {
        nfad: nfad,
    };

    match q.cb {
        None => panic!("no callback registered"),
        Some(callback) => {
            callback(&mut msg);
            },
    }
}

impl Message {
    /// Return the metaheader that wraps the packet
    pub fn get_msg_packet_hdr(&self) -> NfMsgPacketHdr {
        let ptr = unsafe { nflog_get_msg_packet_hdr(self.nfad) };
        let c_hdr = ptr as *const NfMsgPacketHdr;
        let hdr = unsafe {
            // XXX copy structure ??
            NfMsgPacketHdr {
                hw_protocol: (*c_hdr).hw_protocol,
                hook: (*c_hdr).hook,
                pad: (*c_hdr).pad,
            }
        };
        return hdr;
    }

    /// Get the hardware link layer type from logging data
    pub fn get_hwtype(&self) -> u16 {
        return unsafe { nflog_get_hwtype(self.nfad) };
    }



    /// Get the packet mark
    pub fn get_nfmark(&self) -> u32 {
        return unsafe { nflog_get_nfmark(self.nfad) };
    }

    /// Get the packet timestamp
    pub fn get_timestamp(&self) -> Result<libc::timeval,NflogError> {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let rc = unsafe { nflog_get_timestamp(self.nfad,&mut tv) };
        match rc {
            0 => Ok(tv),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Get the interface that the packet was received through
    ///
    /// Returns the index of the device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// input interface is not known (ie. `POSTROUTING`?).
    pub fn get_indev(&self) -> u32 {
        return unsafe { nflog_get_indev(self.nfad) };
    }

    /// Get the physical interface that the packet was received through
    ///
    /// Returns the index of the physical device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// physical input interface is no longer known (ie. `POSTROUTING`?).
    pub fn get_physindev(&self) -> u32 {
        return unsafe { nflog_get_physindev(self.nfad) };
    }

    /// Get the interface that the packet will be routed out
    ///
    /// Returns the index of the device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_outdev(&self) -> u32 {
        return unsafe { nflog_get_outdev(self.nfad) };
    }

    /// Get the physical interface that the packet will be routed out
    ///
    /// Returns the index of the physical device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the physical output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_physoutdev(&self) -> u32 {
        return unsafe { nflog_get_physoutdev(self.nfad) };
    }

    /// Get hardware address
    ///
    /// Retrieves the hardware address associated with the given packet.
    ///
    /// For ethernet packets, the hardware address returned (if any) will be
    /// the MAC address of the packet *source* host.
    ///
    /// The destination MAC address is not
    /// known until after POSTROUTING and a successful ARP request, so cannot
    /// currently be retrieved.
    pub fn get_packet_hw<'a>(&'a self) -> Result<HwAddr<'a>,NflogError> {
        let c_hw = unsafe { nflog_get_packet_hw(self.nfad) };

        if c_hw == std::ptr::null() {
            return Err(NflogError::NoSuchAttribute);
        }

        let c_len = u16::from_be(unsafe{(*c_hw).hw_addrlen}) as usize;
        match c_len {
            0 => Err(NflogError::NoSuchAttribute),
            _ => Ok( HwAddr::new(unsafe{&((*c_hw).hw_addr)[1..c_len]})),
        }
    }

    /// Depending on set_mode, we may not have a payload
    pub fn get_payload<'a>(&'a self) -> &'a [u8] {
        let c_ptr = std::ptr::null_mut();
        let payload_len = unsafe { nflog_get_payload(self.nfad, &c_ptr) };
        let payload : &[u8] = unsafe { std::slice::from_raw_parts(c_ptr as *mut u8, payload_len as usize) };

        return payload;
    }

    /// Return the log prefix as configured using `--nflog-prefix "..."`
    /// in iptables rules.
    pub fn get_prefix(&self) -> Result<String,std::str::Utf8Error> {
        let c_buf: *const libc::c_char = unsafe { nflog_get_prefix(self.nfad) };
        let c_str = unsafe { std::ffi::CStr::from_ptr(c_buf) };
        match c_str.to_str() {
            Err(e) => Err(e),
            Ok(v)  => Ok(v.to_string()),
        }
    }

    /// Available only for outgoing packets
    pub fn get_uid(&self) -> Result<u32,&str> {
        let mut uid =0;
        let rc = unsafe { nflog_get_uid(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err("nflog_get_uid"),
        }
    }

    /// Available only for outgoing packets
    pub fn get_gid(&self) -> Result<u32,NflogError> {
        let mut gid =0;
        let rc = unsafe { nflog_get_gid(self.nfad,&mut gid) };
        match rc {
            0 => Ok(gid),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Get the local nflog sequence number
    /// You must enable this via `set_flags(nflog::CfgFlags::CfgFlagsSeq)`.
    pub fn get_seq(&self) -> Result<u32,NflogError> {
        let mut uid =0;
        let rc = unsafe { nflog_get_seq(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Get the global nflog sequence number
    /// You must enable this via `set_flags(nflog::CfgFlags::CfgFlagsSeqGlobal)`.
    pub fn get_seq_global(&self) -> Result<u32,NflogError> {
        let mut uid =0;
        let rc = unsafe { nflog_get_seq_global(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Print the logged packet in XML format into a buffer
    pub fn as_xml_str(&self, flags: &[XMLFormatFlags]) -> Result<String,std::str::Utf8Error> {
        // if buffer size is smaller than output, nflog_snprintf_xml will fail
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_uchar;
        let buf_len = buf.len() as libc::size_t;

        let xml_flags = flags.iter().map(|flag| {
            match *flag {
                XMLFormatFlags::XmlPrefix => NFLOG_XML_PREFIX,
                XMLFormatFlags::XmlHw => NFLOG_XML_HW,
                XMLFormatFlags::XmlMark => NFLOG_XML_MARK,
                XMLFormatFlags::XmlDev => NFLOG_XML_DEV,
                XMLFormatFlags::XmlPhysDev => NFLOG_XML_PHYSDEV,
                XMLFormatFlags::XmlPayload => NFLOG_XML_PAYLOAD,
                XMLFormatFlags::XmlTime => NFLOG_XML_TIME,
                XMLFormatFlags::XmlAll => NFLOG_XML_ALL,
            }
        }).fold(0u32, |acc, i| acc | i);

        let rc = unsafe { nflog_snprintf_xml(buf_ptr, buf_len, self.nfad, xml_flags) };
        if rc < 0 { panic!("nflog_snprintf_xml"); } // XXX see snprintf error codes

        match std::str::from_utf8(&buf) {
            Ok(v) => Ok(v.to_string()),
            Err(e) => Err(e),
        }
    }
}

use std::fmt;
use std::fmt::Write;

impl fmt::Display for Message {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let payload_data = self.get_payload();
        let mut s = String::new();
        for &byte in payload_data {
            write!(&mut s, "{:X} ", byte).unwrap();
        }
        write!(out, "{}", s)
    }
}



#[cfg(test)]
mod tests {

    extern crate libc;

    #[test]
    fn nflog_open() {
        let mut q = ::Queue::new();

        q.open();

        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!q.qh.is_null());

        q.close();
    }

    #[test]
    #[ignore]
    fn nflog_bind() {
        let mut q = ::Queue::new();

        q.open();

        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!q.qh.is_null());

        let rc = q.bind(libc::AF_INET);
        println!("q.bind: {}", rc);
        assert!(q.bind(libc::AF_INET) == 0);

        q.close();
    }
}
