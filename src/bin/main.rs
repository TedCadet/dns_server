use std::io::Error;
use std::{fs::File, io::Read};

use dns_server::dns_handling::{byte_buffer::BytePacketBuffer, dns_packet::DnsPacket};

fn main() -> Result<(), Error> {
    println!("============ Reading packet ==========");

    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

    println!("- Reading header:");
    println!("{:#?}", packet.header);

    println!("- Reading questions:");
    for q in packet.questions {
        println!("{:#?}", q);
    }

    println!("- Reading answers:");
    for rec in packet.answers {
        println!("{:#?}", rec);
    }

    println!("- Reading authorities:");
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }

    println!("- Reading resources:");
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
