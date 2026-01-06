use std::io::Error;

use super::{
    byte_buffer::BytePacketBuffer, dns_header::DnsHeader, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_type::QueryType,
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    /// create a new DnsPacket containing the header, the questions, the answers, the authorities and the resources
    pub fn new() -> DnsPacket {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// create the DnsPacket from the BytePacketBuffer
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, Error> {
        let mut result = DnsPacket::new();
        result.header.read(buffer).unwrap();

        Self::get_questions(&mut result, buffer).unwrap();
        // get answers
        Self::get_records(result.header.answers, &mut result, buffer).unwrap();
        // get authoritative_entries
        Self::get_records(result.header.authoritative_entries, &mut result, buffer).unwrap();
        // get resource_entries
        Self::get_records(result.header.resource_entries, &mut result, buffer).unwrap();

        Ok(result)
    }

    /// write the BytePacketBuffer from a DnsPacket
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), &'static str> {
        // write the header
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer).unwrap();

        // write the questions and the records
        for question in &self.questions {
            question.write(buffer).unwrap();
        }

        Self::write_records(&self.answers, buffer).unwrap();
        Self::write_records(&self.authorities, buffer).unwrap();
        Self::write_records(&self.resources, buffer).unwrap();

        Ok(())
    }

    fn get_questions(result: &mut DnsPacket, buffer: &mut BytePacketBuffer) -> Result<(), Error> {
        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer).unwrap();
            result.questions.push(question);
        }

        Ok(())
    }

    fn get_records(
        num_records: u16,
        result: &mut DnsPacket,
        buffer: &mut BytePacketBuffer,
    ) -> Result<(), Error> {
        for _ in 0..num_records {
            let rec = DnsRecord::read(buffer).unwrap();
            result.answers.push(rec);
        }

        Ok(())
    }

    fn write_records(
        records: &Vec<DnsRecord>,
        buffer: &mut BytePacketBuffer,
    ) -> Result<(), &'static str> {
        for rec in records {
            rec.write(buffer).unwrap();
        }

        Ok(())
    }
}
