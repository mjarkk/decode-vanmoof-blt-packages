pub mod att;
mod hci_acl;
mod hci_event;

use std::collections::HashMap;

pub use att::*;
pub use hci_acl::*;
pub use hci_event::*;

pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new(b: Vec<u8>) -> Self {
        Self(b)
    }
    // Reading direction: ->
    pub fn drain_u32_big_endian(&mut self) -> u32 {
        u32::from_be_bytes(self.0.drain(..4).collect::<Vec<u8>>().try_into().unwrap())
    }
    // Reading direction: <-
    pub fn drain_u16_little_endian(&mut self) -> u16 {
        u16::from_le_bytes(self.0.drain(..2).collect::<Vec<u8>>().try_into().unwrap())
    }
    // Reading direction: <-
    pub fn drain_u32_little_endian(&mut self) -> u32 {
        u32::from_le_bytes(self.0.drain(..4).collect::<Vec<u8>>().try_into().unwrap())
    }
    pub fn drain_vec(&mut self, range: impl Into<usize>) -> Vec<u8> {
        self.0.drain(..range.into()).collect()
    }
    pub fn drain_bytes(&mut self, range: usize) -> Bytes {
        Self(self.drain_vec(range))
    }
    pub fn drain(&mut self, range: impl Into<usize>) {
        self.0.drain(..range.into());
    }
    pub fn drain_one(&mut self) -> u8 {
        *self.0.drain(..1).as_slice().first().unwrap()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn seek(&mut self, range: impl Into<usize>) -> &[u8] {
        &self.0[..range.into()]
    }
    pub fn vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

pub struct BltPacket {
    pub nr: usize,
    pub kind: BltPacketKind,
}

pub enum BltPacketKind {
    MetaEvent(BltEventMeta),
    RawAtt(RawAtt),
}

pub struct Parser {
    continueing_fragment_for_conn_handle: HashMap<u16, BltHciAclContinueingFragment>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            continueing_fragment_for_conn_handle: HashMap::new(),
        }
    }
    pub fn parse(&mut self, mut b: Bytes, nr: usize) -> Option<BltPacket> {
        let first = b.drain_one();
        let second = b.seek(1u8)[0];

        let kind = match (first, second) {
            // Blt Hci Command:
            (_, v) if v & 0xfc == (0x3f << 2) => None, // 1111 11.. .... .... = Opcode Group Field: Vendor-Specific Commands (0x3f)
            (_, v) if v & 0xfc == (0x01 << 2) => None, // 0000 01.. .... .... = Opcode Group Field: Link Control Commands (0x01)
            (0x05, v)
            | (0x0c, v)
            | (0x0b, v)
            | (0x0d, v)
            | (0x11, v)
            | (0x12, v)
            | (0x16, v)
            | (0x20, v)
                if v == (0x08 << 2) =>
            // 0010 00.. .... .... = Opcode Group Field: LE Controller Commands (0x08)
            // These bits always seems to be zero .... ..00 .... ....
            // Hence why we don't zero them out above using: (& 0xfc)
            {
                None
            }
            (_, v) if v & 0xfc == (0x05 << 2) => None, // 0001 01.. .... .... = Opcode Group Field: Status Parameters (0x05)

            // Blt Hci events:
            (0x01, _) => None, // Inquiry Complete
            (0x0c, _) => None, // Read Remote Version Information Complete
            (0x0e, _) => None, // Command Complete
            (0x0f, _) => None, // Command Status
            (0x13, _) => None, // Number of Completed Packets
            (0x2f, _) => None, // Extended Inquiry Result
            (0x3e, _) => BltEventMeta::parse(&mut b, nr).map(|ev| BltPacketKind::MetaEvent(ev)),

            // Blt Hci Acl
            (first, second) if is_blt_hci_acl(second) => {
                // ..10 .... .... .... = PB Flag: First Automatically Flushable Packet (2)
                // ..01 .... .... .... = PB Flag: Continuing Fragment (1)
                let handle = (first as u16 | (second as u16) << 8) & 0x0fff;
                b.drain_one();
                parse_blt_hci_acl(self, &mut b, handle, nr).map(|v| BltPacketKind::RawAtt(v))
            }
            _ => None,
        };

        kind.map(|kind| BltPacket { nr, kind })
    }
}

fn is_blt_hci_acl(bt: u8) -> bool {
    // With vm bikes this flag always seems to be this value
    // 00.. .... .... .... = BC Flag: Point-To-Point (0)
    if bt & (0x03 << 6) != 0 {
        return false;
    }

    // ..10 .... .... .... = PB Flag: First Automatically Flushable Packet (2)
    // ..01 .... .... .... = PB Flag: Continuing Fragment (1)
    match (bt >> 4) & 0x03 {
        0x01 => true,
        0x02 => true,
        0x00 => true,
        _ => false, // 0x03
    }
}
