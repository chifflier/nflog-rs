extern crate libc;
extern crate nflog;

use std::fmt::Write;

fn log_callback(msg: nflog::Message) {
    println!("Packet received\n");
    println!(
        " -> uid: {}, gid: {}",
        msg.get_uid().unwrap_or(0xffff),
        msg.get_gid().unwrap_or(0xffff)
    );
    println!(" -> prefix: {}", msg.get_prefix().unwrap());
    println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));

    let payload_data = msg.get_payload();
    let mut s = String::new();
    for &byte in payload_data {
        write!(&mut s, "{:02X} ", byte).unwrap();
    }
    println!("{}", s);

    let hwaddr = msg.get_packet_hw().unwrap_or_default();
    println!("{}", hwaddr);

    println!("XML\n{}", msg.as_xml_str(nflog::XMLFormat::All).unwrap());
}

fn main() {
    let queue = nflog::Queue::open().unwrap();

    println!("nflog example program: print packets metadata");

    let _ = queue.unbind(libc::AF_INET); // ignore result, failure is not critical here

    queue.bind(libc::AF_INET).unwrap();

    let mut group = queue.bind_group(0).unwrap();

    group.set_mode(nflog::CopyMode::Packet, 0xffff);
    //group.set_nlbufsiz(0xffff);
    //group.set_timeout(1500);

    group.set_flags(nflog::Flags::Sequence);

    group.set_callback(Box::new(log_callback));
    queue.run_loop();
}
