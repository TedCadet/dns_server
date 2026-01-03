use std::io::Error;

use crate::lib::{byte_buffer::BytePacketBuffer, query_type::QueryType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Error> {
        buffer.read_qname(&mut self.name).unwrap();
        self.qtype = QueryType::from_num(buffer.read_u16().unwrap());
        let _ = buffer.read_u16().unwrap();

        Ok(())
    }
}
