pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new(b: Vec<u8>) -> Self {
        Self(b)
    }
    pub fn drain_u32_big_endian(&mut self) -> u32 {
        u32::from_be_bytes(self.0.drain(..4).collect::<Vec<u8>>().try_into().unwrap())
    }
    pub fn drain_vec(&mut self, range: usize) -> Vec<u8> {
        self.0.drain(..range).collect()
    }
    pub fn drain_bytes(&mut self, range: usize) -> Bytes {
        Self(self.drain_vec(range))
    }
    pub fn drain(&mut self, range: usize) {
        self.0.drain(..range);
    }
    pub fn drain_one(&mut self) -> u8 {
        *self.0.drain(..1).as_slice().first().unwrap()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct BltPacket {
    nr: usize,
    kind: BltPacketKind,
}

pub enum BltPacketKind {
    Event(BltEvent),
}

impl BltPacket {
    pub fn parse(mut b: Bytes, nr: usize) -> Option<Self> {
        let kind = match b.drain_one() {
            0x3e => Some(BltPacketKind::Event(BltEvent::parse(&mut b, nr))),
            _ => None,
        };

        if let Some(kind) = kind {
            Some(Self { nr, kind })
        } else {
            None
        }
    }
}

pub enum BltEvent {
    AdvertizingReport,
    EnhancedConnectionComplete,
    UnimportantSubEvent(u8),
    UnknownSubEvent(u8),
}

impl BltEvent {
    fn parse(b: &mut Bytes, nr: usize) -> Self {
        b.drain_one(); // parameter_total_len
        let sub_event = b.drain_one();
        match sub_event {
            0x02 => {
                // Sub Event: LE Advertizing report (0x02)
                Self::AdvertizingReport
            }
            0x0a => {
                // Sub Event: LE Enhanced Connection Complete (0x0a)
                Self::EnhancedConnectionComplete
            }
            0x04 | 0x06 | 0x03 => {
                // Sub Event: LE Connection Update Complete (0x03)
                // Sub Event: LE Read Remote Features Complete (0x04)
                // Sub Event: LE Remote Connection Parameter Request (0x06)
                // These sub commands do not contain any vauluable information
                Self::UnimportantSubEvent(sub_event)
            }
            _ => Self::UnknownSubEvent(sub_event),
        }
    }
}
