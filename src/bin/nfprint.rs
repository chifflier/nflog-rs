extern crate nflog;
extern crate libc;

use std::fmt::Write;

fn log_callback(msg: nflog::Message) {
    println!("Packet received\n");
    println!(" -> msg: {}", msg);
    println!(" -> uid: {}, gid: {}", msg.get_uid().unwrap_or(0xffff), msg.get_gid().unwrap_or(0xffff));
    println!(" -> prefix: {}", msg.get_prefix().unwrap());
    println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));

    let payload_data = msg.get_payload();
    let mut s = String::new();
    for &byte in payload_data {
        write!(&mut s, "{:02X} ", byte).unwrap();
    }
    println!("{}", s);

    let hwaddr = msg.get_packet_hw().unwrap_or(nflog::HwAddr::new(&[]));
    println!("{}", hwaddr);

    println!("XML\n{}", msg.as_xml_str(&[nflog::XMLFormatFlags::XmlAll]).unwrap());
}

fn main() {
    let mut q = nflog::Queue::new();

    println!("nflog example program: print packets metadata");

    q.open();
    q.unbind(libc::AF_INET); // ignore result, failure is not critical here

    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.bind_group(0);

    q.set_mode(nflog::CopyMode::CopyPacket, 0xffff);
    //q.set_nlbufsiz(0xffff);
    //q.set_timeout(1500);

    q.set_flags(nflog::CfgFlags::CfgFlagsSeq);

    q.set_callback(log_callback);
    q.run_loop();

    q.close();
}
