extern crate libc;

use hwaddr::*;
use std;

type NflogData = *const libc::c_void;

/// Opaque struct `Message`: abstracts NFLOG data representing a packet data and metadata
pub struct Message {
    nfad : NflogData,
}

#[derive(Debug)]
pub enum NflogError {
    NoSuchAttribute,
}

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

#[link(name = "netfilter_log")]
extern {
    // message parsing functions
    fn nflog_get_msg_packet_hdr(nfad: NflogData) -> *const libc::c_void;
    fn nflog_get_hwtype (nfad: NflogData) -> u16;
    fn nflog_get_msg_packet_hwhdrlen (nfad: NflogData) -> u16;
    fn nflog_get_msg_packet_hwhdr (nfad: NflogData) -> *const libc::c_char;
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
}

const NFLOG_XML_PREFIX  : u32  = (1 << 0);
const NFLOG_XML_HW      : u32  = (1 << 1);
const NFLOG_XML_MARK    : u32  = (1 << 2);
const NFLOG_XML_DEV     : u32  = (1 << 3);
const NFLOG_XML_PHYSDEV : u32  = (1 << 4);
const NFLOG_XML_PAYLOAD : u32  = (1 << 5);
const NFLOG_XML_TIME    : u32  = (1 << 6);
const NFLOG_XML_ALL     : u32  = (!0u32);

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

impl Message {
    /// Create a `Messsage` from a valid NflogData pointer
    ///
    /// **This function should never be called directly**
    #[doc(hidden)]
    pub fn new(nfad: *const libc::c_void) -> Message {
        Message {
            nfad: nfad,
        }
    }

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

    /// Get the hardware link layer header
    pub fn get_packet_hwhdr<'a>(&'a self) -> &'a [u8] {
        let c_len = unsafe { nflog_get_msg_packet_hwhdrlen(self.nfad) };
        let c_ptr = unsafe { nflog_get_msg_packet_hwhdr(self.nfad) };
        let data : &[u8] = unsafe { std::slice::from_raw_parts(c_ptr as *mut u8, c_len as usize) };
        return data;
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

    /// Get payload
    ///
    /// Depending on set_mode, we may not have a payload
    /// The actual amount and type of data retrieved by this function will
    /// depend on the mode set with the `set_mode()` function.
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


