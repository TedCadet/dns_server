use std::io::Error;

use super::{byte_buffer::BytePacketBuffer, result_code::ResultCode};

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recusrion_desired: bool, // 1 bit, Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
    pub truncated_message: bool, // 1 bit, Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
    pub authoritative_answer: bool, // 1 bit, Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
    pub opcode: u8,                 // 4 bits, Typically always 0, see RFC1035 for details.
    pub response: bool,             // 1 bit, 0 for queries, 1 for responses.

    pub rescode: ResultCode, // 4 bits, Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
    pub checking_disabled: bool, // 1 bit,
    pub authed_data: bool,   // 1 bit,
    pub z: bool, // 1 bit, Originally reserved for later use, but now used for DNSSEC queries.
    pub recursion_available: bool, // 1 bit, Set by the server to indicate whether or not recursive queries are allowed.

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            recusrion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Error> {
        self.id = buffer.read_u16().unwrap();

        let flags = buffer.read_u16().unwrap();
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recusrion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16().unwrap();
        self.answers = buffer.read_u16().unwrap();
        self.authoritative_entries = buffer.read_u16().unwrap();
        self.resource_entries = buffer.read_u16().unwrap();

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), &'static str> {
        buffer.write_u16(self.id).unwrap();

        let first_group_byte_after_id = (self.recusrion_desired as u8)
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | (self.opcode << 3)
            | ((self.response as u8) << 7) as u8;

        buffer.write_u8(first_group_byte_after_id).unwrap();

        let second_group_byte_after_id = (self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7);

        buffer.write_u8(second_group_byte_after_id).unwrap();

        buffer.write_u16(self.questions).unwrap();
        buffer.write_u16(self.answers).unwrap();
        buffer.write_u16(self.authoritative_entries).unwrap();
        buffer.write_u16(self.resource_entries).unwrap();

        Ok(())
    }
}
