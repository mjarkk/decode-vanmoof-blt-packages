mod event;
mod hci_acl;

pub use event::*;
pub use hci_acl::*;

pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new(b: Vec<u8>) -> Self {
        Self(b)
    }
    pub fn drain_u32_big_endian(&mut self) -> u32 {
        u32::from_be_bytes(self.0.drain(..4).collect::<Vec<u8>>().try_into().unwrap())
    }
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
}

pub struct BltPacket {
    nr: usize,
    kind: BltPacketKind,
}

pub enum BltPacketKind {
    MetaEvent(BltEventMeta),
}

impl BltPacket {
    pub fn parse(mut b: Bytes, nr: usize) -> Option<Self> {
        let kind = match (b.drain_one(), b.seek(1u8)[0]) {
            // Blt Hci events:
            (0x01, _) => None, // BLT HCI Event: Inquiry Complete
            (0x0c, _) => None, // BLT HCI Event: Read Remote Version Information Complete
            (0x0e, _) => None, // BLT HCI Event: Command Complete
            (0x0f, _) => None, // BLT HCI Event: Command Status
            (0x13, _) => None, // BLT HCI Event: Number of Completed Packets
            (0x2f, _) => None, // BLT HCI Event: Extended Inquiry Result
            (0x3e, _) => BltEventMeta::parse(&mut b, nr).map(|ev| BltPacketKind::MetaEvent(ev)),
            //
            _ => None,
        };

        kind.map(|kind| Self { nr, kind })
    }
}
