use std::io::Error;
use std::net::UdpSocket;

use dns_server::dns_handling::dns_question::DnsQuestion;
use dns_server::dns_handling::query_type::QueryType;
use dns_server::dns_handling::{byte_buffer::BytePacketBuffer, dns_packet::DnsPacket};

fn main() -> Result<(), Error> {
    // Perform an A query for google.com
    let qname = "google.com";
    let qtype = QueryType::A;

    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 7777;
    packet.header.questions = 1;
    packet.header.recusrion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos()], server)?;

    // to prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // as per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response
    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();

    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
