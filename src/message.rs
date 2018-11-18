use libc;

use nflog_sys::*;

use hwaddr::*;
use std;
use std::ptr::NonNull;
use std::time;
use std::marker::PhantomData;

/// Opaque struct `Message`: abstracts NFLOG data representing a packet data and metadata
#[derive(Debug)]
pub struct Message<'a> {
    inner: NonNull<nflog_data>,
    _lifetime: PhantomData<&'a nflog_data>
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NflogError {
    NoSuchAttribute,
}

bitflags! {
    /// XML formatting flags
    pub struct XMLFormat: u32 {
        const Prefix = NFLOG_XML_PREFIX;
        const Hw = NFLOG_XML_HW;
        const Mark = NFLOG_XML_MARK;
        const Dev = NFLOG_XML_DEV;
        const PhysDev = NFLOG_XML_PHYSDEV;
        const Payload = NFLOG_XML_PAYLOAD;
        const Time = NFLOG_XML_TIME;
        const All = NFLOG_XML_ALL;
    }
}

impl Default for XMLFormat {
    fn default() -> Self {
        XMLFormat::All
    }
}

impl<'a> Message<'a> {
    /// Create a `Message` from a valid nflog_data pointer
    /// Unsafe because the lifetime is made up, and the pointer must be valid
    pub(crate) unsafe fn new(inner: *mut nflog_data) -> Self {
        Message {
            inner: NonNull::new(inner).expect("non-null nflog_data"),
            _lifetime: PhantomData,
        }
    }

    /// Get the hardware link layer type from logging data
    pub fn get_hwtype(&self) -> u16 {
        unsafe { nflog_get_hwtype(self.inner.as_ptr()) }
    }

    /// Get the hardware link layer header
    pub fn get_packet_hwhdr(&self) -> &'a [u8] {
        let len = unsafe { nflog_get_msg_packet_hwhdrlen(self.inner.as_ptr()) };
        let ptr = unsafe { nflog_get_msg_packet_hwhdr(self.inner.as_ptr()) };
        let data: &[u8] = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
        return data;
    }

    /// Returns the layer 3 protocol/EtherType of the packet (i.e. 0x0800 is IPv4)
    pub fn get_l3_proto(&self) -> u16 {
        let packet_hdr = unsafe { *nflog_get_msg_packet_hdr(self.inner.as_ptr()) };
        u16::from_be(packet_hdr.hw_protocol)
    }

    /// Get the packet mark
    pub fn get_nfmark(&self) -> u32 {
        unsafe { nflog_get_nfmark(self.inner.as_ptr()) }
    }

    /// Get the packet timestamp
    pub fn get_timestamp(&self) -> Result<time::SystemTime, NflogError> {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let rc = unsafe { nflog_get_timestamp(self.inner.as_ptr(), &mut tv) };
        if rc != 0 {
            return Err(NflogError::NoSuchAttribute);
        }

        let tv_duration = time::Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000);
        Ok(time::UNIX_EPOCH + tv_duration)
    }

    /// Get the interface that the packet was received through
    ///
    /// Returns the index of the device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// input interface is not known (ie. `POSTROUTING`?).
    pub fn get_indev(&self) -> u32 {
        unsafe { nflog_get_indev(self.inner.as_ptr()) }
    }

    /// Get the physical interface that the packet was received through
    ///
    /// Returns the index of the physical device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// physical input interface is no longer known (ie. `POSTROUTING`?).
    pub fn get_physindev(&self) -> u32 {
        unsafe { nflog_get_physindev(self.inner.as_ptr()) }
    }

    /// Get the interface that the packet will be routed out
    ///
    /// Returns the index of the device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_outdev(&self) -> u32 {
        unsafe { nflog_get_outdev(self.inner.as_ptr()) }
    }

    /// Get the physical interface that the packet will be routed out
    ///
    /// Returns the index of the physical device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the physical output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_physoutdev(&self) -> u32 {
        unsafe { nflog_get_physoutdev(self.inner.as_ptr()) }
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
    pub fn get_packet_hw(&self) -> Result<HwAddr, NflogError> {
        let c_hw = unsafe { nflog_get_packet_hw(self.inner.as_ptr()) };

        if c_hw.is_null() {
            return Err(NflogError::NoSuchAttribute);
        }

        let c_len = u16::from_be(unsafe{(*c_hw).hw_addrlen});
        if c_len == 0 {
            return Err(NflogError::NoSuchAttribute);
        }
        Ok(HwAddr{
            len: c_len as u8,
            inner: unsafe {(*c_hw).hw_addr},
        })
    }

    /// Get payload
    ///
    /// Depending on set_mode, we may not have a payload
    /// The actual amount and type of data retrieved by this function will
    /// depend on the mode set with the `set_mode()` function.
    pub fn get_payload(&self) -> &'a [u8] {
        let mut c_ptr = std::ptr::null_mut();
        let payload_len = unsafe { nflog_get_payload(self.inner.as_ptr(), &mut c_ptr) };
        let payload = unsafe { std::slice::from_raw_parts(c_ptr as *const u8, payload_len as usize) };

        return payload;
    }

    /// Return the log prefix as configured using `--nflog-prefix "..."`
    /// in iptables rules.
    pub fn get_prefix(&self) -> Result<String,std::str::Utf8Error> {
        let c_buf: *const libc::c_char = unsafe { nflog_get_prefix(self.inner.as_ptr()) };
        let c_str = unsafe { std::ffi::CStr::from_ptr(c_buf) };
        match c_str.to_str() {
            Err(e) => Err(e),
            Ok(v)  => Ok(v.to_string()),
        }
    }

    /// Available only for outgoing packets
    pub fn get_uid(&self) -> Result<u32,NflogError> {
        let mut uid =0;
        let rc = unsafe { nflog_get_uid(self.inner.as_ptr(),&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Available only for outgoing packets
    pub fn get_gid(&self) -> Result<u32,NflogError> {
        let mut gid =0;
        let rc = unsafe { nflog_get_gid(self.inner.as_ptr(),&mut gid) };
        match rc {
            0 => Ok(gid),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Get the local nflog sequence number
    /// You must enable this via `set_flags(nflog::CfgFlags::CfgFlagsSeq)`.
    pub fn get_seq(&self) -> Result<u32,NflogError> {
        let mut seq =0;
        let rc = unsafe { nflog_get_seq(self.inner.as_ptr(),&mut seq) };
        match rc {
            0 => Ok(seq),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Get the global nflog sequence number
    /// You must enable this via `set_flags(nflog::CfgFlags::CfgFlagsSeqGlobal)`.
    pub fn get_seq_global(&self) -> Result<u32,NflogError> {
        let mut seq =0;
        let rc = unsafe { nflog_get_seq_global(self.inner.as_ptr(),&mut seq) };
        match rc {
            0 => Ok(seq),
            _ => Err(NflogError::NoSuchAttribute),
        }
    }

    /// Print the logged packet in XML format into a buffer
    pub fn as_xml_str(&self, flags: XMLFormat) -> Result<String, std::string::FromUtf8Error> {
        // if buffer size is smaller than output, nflog_snprintf_xml will fail
        let mut buf = Vec::with_capacity(0xFFFF);

        let mut rc = unsafe { nflog_snprintf_xml(buf.as_mut_ptr() as *mut _, buf.capacity(), self.inner.as_ptr(), flags.bits() as _) };
        if rc < 0 { panic!("nflog_snprintf_xml"); } // XXX see snprintf error codes
        if rc as usize > buf.capacity() {
            let diff = rc as usize - buf.capacity();
            buf.reserve_exact(diff);
            rc = unsafe { nflog_snprintf_xml(buf.as_mut_ptr() as *mut _, buf.capacity(), self.inner.as_ptr(), flags.bits() as _) };
            if rc < 0 { panic!("nflog_snprintf_xml"); } // XXX see snprintf error codes
        }

        unsafe { buf.set_len(rc as usize) };
        buf.shrink_to_fit();
        match String::from_utf8(buf) {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }
}
