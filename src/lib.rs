extern crate libc;

type NflogHandle = *const libc::c_void;
type NflogGroupHandle = *const libc::c_void;

pub type NflogCallback = fn (&Payload) -> ();

type NflogData = *const libc::c_void;
type NflogCCallback = extern "C" fn (*const libc::c_void, *const libc::c_void, *const libc::c_void, *const libc::c_void );

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



// Copy modes
pub const NFULNL_COPY_NONE : u8   = 0x00;
pub const NFULNL_COPY_META : u8   = 0x01;
pub const NFULNL_COPY_PACKET : u8 = 0x02;

// Flags
pub const NFULNL_CFG_F_SEQ : u16         = 0x0001;
pub const NFULNL_CFG_F_SEQ_GLOBAL : u16  = 0x0001;

// XML formatting flags
pub const NFLOG_XML_PREFIX  : u32  = (1 << 0);
pub const NFLOG_XML_HW      : u32  = (1 << 1);
pub const NFLOG_XML_MARK    : u32  = (1 << 2);
pub const NFLOG_XML_DEV     : u32  = (1 << 3);
pub const NFLOG_XML_PHYSDEV : u32  = (1 << 4);
pub const NFLOG_XML_PAYLOAD : u32  = (1 << 5);
pub const NFLOG_XML_TIME    : u32  = (1 << 6);
pub const NFLOG_XML_ALL     : u32  = (!0u32);



pub struct Log {
    q  : NflogHandle,
    g  : NflogGroupHandle,
    cb : Option<NflogCallback>,
}

pub struct Payload {
    //q    : NflogHandle,
    //g    : NflogGroupHandle,
    nfad : NflogData,
}


pub fn hello() -> u8 {
    println!("hello\n");
    return 1u8;
}

impl Log {
    pub fn new() -> Log {
        return Log {
            q : std::ptr::null_mut(),
            g : std::ptr::null_mut(),
            cb: None,
        };
    }

    pub fn open(&mut self) {
        self.q = unsafe { nflog_open() };
    }

    pub fn close(&mut self) {
        unsafe { nflog_close(self.q) };
        self.q = std::ptr::null_mut();
    }

    // requires root privileges
    pub fn bind(&self, pf: libc::c_int) -> i32 {
        assert!(!self.q.is_null());
        return unsafe { nflog_bind_pf(self.q,pf) };
    }

    // requires root privileges
    pub fn unbind(&self, pf: libc::c_int) -> i32 {
        assert!(!self.q.is_null());
        return unsafe { nflog_unbind_pf(self.q,pf) }
    }

    // requires root privileges
    pub fn fd(&self) -> i32 {
        assert!(!self.q.is_null());
        return unsafe { nflog_fd(self.q) }
    }

    // requires root privileges
    pub fn bind_group(&mut self, num: u16) {
        assert!(!self.q.is_null());
        self.g = unsafe { nflog_bind_group(self.q,num) }
    }

    // requires root privileges
    pub fn unbind_group(&mut self) {
        assert!(!self.g.is_null());
        unsafe { nflog_unbind_group(self.g); }
        self.g = std::ptr::null_mut();
    }

    // requires root privileges
    pub fn set_mode(&self, mode: u8, range: u32) {
        assert!(!self.g.is_null());
        unsafe { nflog_set_mode(self.g, mode, range); }
    }

    // requires root privileges
    pub fn set_timeout(&self, timeout: u32) {
        assert!(!self.g.is_null());
        unsafe { nflog_set_timeout(self.g, timeout); }
    }

    // requires root privileges
    pub fn set_qthresh(&self, qthresh: u32) {
        assert!(!self.g.is_null());
        unsafe { nflog_set_qthresh(self.g, qthresh); }
    }

    // requires root privileges
    pub fn set_nlbufsiz(&self, nlbufsiz: u32) {
        assert!(!self.g.is_null());
        unsafe { nflog_set_nlbufsiz(self.g, nlbufsiz); }
    }

    // requires root privileges
    pub fn set_flags(&self, flags: u16) {
        assert!(!self.g.is_null());
        unsafe { nflog_set_flags(self.g, flags); }
    }



    pub fn set_callback(&mut self, cb: NflogCallback) {
        println!("cb: {:p}", cb as *const());
        self.cb = Some(cb);
        let self_ptr = unsafe { std::mem::transmute(&*self) };
        println!("self_ptr: {:p}", self_ptr);
        unsafe {
            println!("nflog_callback_register: {:p}", real_callback as *const());
            nflog_callback_register(self.g, real_callback, self_ptr);
        }
    }

    pub fn run_loop(&self) {
        assert!(!self.g.is_null());
        println!("self: {:p}", self as * const _);

        let fd = self.fd();
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        println!("  self.g: {:p}", self.g as *const());
        loop {
            let rc;
            unsafe {
                rc = libc::recv(fd,buf_ptr,buf_len,0);
                if rc < 0 { panic!("error in recv()"); };
            }

            println!("RECV: {}\n", rc);
            if rc >= 0 {
                unsafe {
                    println!("before nflog_handle_packet");
                    let rv = nflog_handle_packet(self.q, buf_ptr, rc as libc::c_int);
                    println!("after nflog_handle_packet: {}", rv);
                }
            }
        }

        //println!("end of loop\n");
    }
}

#[no_mangle]
pub extern "C" fn real_callback(g: *const libc::c_void, nfmsg: *const libc::c_void, nfad: *const libc::c_void, data: *const libc::c_void ) {
    println!("real_callback\n");
    println!("  g:     {:p}", g as *const());
    println!("  nfmsg: {:p}", nfmsg as *const());
    println!("  nfad:  {:p}", nfad as *const());
    println!("  data:  {:p}", data as *const());

    let raw : *mut Log;
    unsafe {
        raw = std::mem::transmute(data);
    }

    let ref mut log = unsafe { &*raw };
    let mut payload = Payload {
        //q:    log.q,
        //g:    g,
        nfad: nfad,
    };
    println!("log: {:p}", log as * const _);

    match log.cb {
        None => panic!("no callback registered"),
        Some(callback) => {
            println!("cb: {:p}", callback as *const());
            callback(&mut payload);
            },
    }

    //panic!("oops");
}

impl Payload {
    // return the metaheader that wraps the packet
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

    // get the hardware link layer type from logging data
    pub fn get_hwtype(&self) -> u16 {
        return unsafe { nflog_get_hwtype(self.nfad) };
    }



    // get the packet mark
    pub fn get_nfmark(&self) -> u32 {
        return unsafe { nflog_get_nfmark(self.nfad) };
    }




    // depending on set_mode, we may not have a payload
    pub fn get_payload(&self) -> &[u8] {
        let c_ptr = std::ptr::null_mut();
        let payload_len = unsafe { nflog_get_payload(self.nfad, &c_ptr) };
        println!("  payload len: {}", payload_len);
        println!("  payload:     {:p}", c_ptr as *const());
        let payload : &[u8] = unsafe { std::slice::from_raw_parts(c_ptr as *mut u8, payload_len as usize) };

        return payload;
    }

    // return the log prefix as configured using --nflog-prefix "..."
    pub fn get_prefix(&self) -> Result<String,std::str::Utf8Error> {
        let c_buf: *const libc::c_char = unsafe { nflog_get_prefix(self.nfad) };
        let c_str = unsafe { std::ffi::CString::from_raw(c_buf as *mut i8) };
        match c_str.to_str() {
            Err(e) => Err(e),
            Ok(v)  => Ok(v.to_string()),
        }
    }

    // available only for outgoing packets
    pub fn get_uid(&self) -> Result<u32,&str> {
        let mut uid =0;
        let rc = unsafe { nflog_get_uid(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err("nflog_get_uid"),
        }
    }

    // available only for outgoing packets
    pub fn get_gid(&self) -> Result<u32,&str> {
        let mut gid =0;
        let rc = unsafe { nflog_get_gid(self.nfad,&mut gid) };
        match rc {
            0 => Ok(gid),
            _ => Err("nflog_get_gid"),
        }
    }

    // get the local nflog sequence number
    // You must enable this via set_flags(nflog::NFULNL_CFG_F_SEQ).
    pub fn get_seq(&self) -> Result<u32,&str> {
        let mut uid =0;
        let rc = unsafe { nflog_get_seq(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err("nflog_get_seq"),
        }
    }

    // get the global nflog sequence number
    // You must enable this via set_flags(nflog::NFULNL_CFG_F_SEQ_GLOBAL).
    pub fn get_seq_global(&self) -> Result<u32,&str> {
        let mut uid =0;
        let rc = unsafe { nflog_get_seq_global(self.nfad,&mut uid) };
        match rc {
            0 => Ok(uid),
            _ => Err("nflog_get_seq_global"),
        }
    }

    // print the logged packet in XML format into a buffer
    pub fn as_xml_str(&self, flags: u32) -> Result<String,std::str::Utf8Error> {
        // XXX make sure buffer size is greater or equal than packet size
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_uchar;
        let buf_len = buf.len() as libc::size_t;

        let rc = unsafe { nflog_snprintf_xml(buf_ptr, buf_len, self.nfad, flags) };
        if rc < 0 { panic!("nflog_snprintf_xml"); } // XXX see snprintf error codes

        match std::str::from_utf8(&buf) {
            Ok(v) => Ok(v.to_string()),
            Err(e) => Err(e),
        }
    }
}

#[repr(C)]
pub struct NfMsgPacketHdr {
    pub hw_protocol : u16, // hw protocol (network order)
    pub hook : u8,
    pub pad : u8,
}




#[cfg(test)]
mod tests {

    extern crate libc;

    #[test]
    fn it_works() {
        assert_eq!(::hello(),1u8);
    }

    #[test]
    fn nflog_open() {
        let mut log = ::Log::new();

        log.open();

        let raw = log.q as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!log.q.is_null());

        log.close();
    }

    #[test]
    #[ignore]
    fn nflog_bind() {
        let mut log = ::Log::new();

        log.open();

        let raw = log.q as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!log.q.is_null());

        let rc = log.bind(libc::AF_INET);
        println!("log.bind: {}", rc);
        assert!(log.bind(libc::AF_INET) == 0);

        log.close();
    }
}
