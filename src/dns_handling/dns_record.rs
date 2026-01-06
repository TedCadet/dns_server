use super::{byte_buffer::BytePacketBuffer, query_type::QueryType};
use std::{io::Error, net::Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, Error> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();

        let qtype_num = buffer.read_u16().unwrap();
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16().unwrap();
        let ttl = buffer.read_u32().unwrap();
        let data_len = buffer.read_u16().unwrap();

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32().unwrap();
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize).unwrap();

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, &'static str> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::A.to_num()).unwrap();
                // the class, in practice always set to 1
                buffer.write_u16(1).unwrap();
                buffer.write_u32(ttl).unwrap();
                // Length of the record
                buffer.write_u16(4).unwrap();

                let addr_octets = addr.octets();
                buffer.write_u8(addr_octets[0]).unwrap();
                buffer.write_u8(addr_octets[1]).unwrap();
                buffer.write_u8(addr_octets[2]).unwrap();
                buffer.write_u8(addr_octets[3]).unwrap();
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
