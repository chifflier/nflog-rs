extern crate nflog;
extern crate libc;

use std::fmt::Write;

fn hello_rust(payload: &nflog::Payload) {
    println!("Packet received\n");

    println!(" -> uid: {}, gid: {}", payload.get_uid().unwrap_or(0xffff), payload.get_gid().unwrap_or(0xffff));
    println!(" -> prefix: {}", payload.get_prefix().unwrap());
    //println!(" -> payload: {}", payload.get_payload());
    println!(" -> seq: {}", payload.get_seq().unwrap_or(0xffff));

    let payload_data = payload.get_payload();

    let mut s = String::new();
    for &byte in payload_data {
        write!(&mut s, "{:X} ", byte).unwrap();
    }
    println!("{}", s);

    println!("XML\n{}", payload.as_xml_str(nflog::NFLOG_XML_ALL).unwrap());

}

fn main() {
    let mut log = nflog::Log::new();

    println!("nflog example program: print packets metadata");

    log.open();
    log.unbind(libc::AF_INET); // ignore result, failure is not critical here


    let rc = log.bind(libc::AF_INET);
    assert!(rc == 0);



    log.bind_group(0);


    log.set_mode(nflog::NFULNL_COPY_PACKET, 0xffff);
    //log.set_nlbufsiz(0xffff);
    //log.set_timeout(1500);

    log.set_flags(nflog::NFULNL_CFG_F_SEQ);


    log.set_callback(hello_rust);
    log.run_loop();







    log.close();
}
