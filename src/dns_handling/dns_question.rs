use std::io::Error;

use super::{byte_buffer::BytePacketBuffer, query_type::QueryType};

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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), &'static str> {
        buffer.write_qname(&self.name).unwrap();

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum).unwrap();
        buffer.write_u16(1).unwrap();

        Ok(())
    }
}
