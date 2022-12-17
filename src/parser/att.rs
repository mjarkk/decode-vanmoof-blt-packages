use std::ops::Add;

use super::Bytes;

pub enum RawAtt {
    ReadRequest(u16), // The argument is the handle
    ReadResponse(Vec<u8>),
    WriteRequest(u16, Vec<u8>), // The first argument is the handle
    WriteResponse(Vec<u8>),
    ReadByGroupTypeResponse(Vec<AttributeGroupData>),
    ReadByTypeRespense(Vec<AttributeData>),
}

impl RawAtt {
    pub fn parse(b: &mut Bytes, attribute_protocol: u16, nr: usize) -> Option<Self> {
        if attribute_protocol != 0x0004 {
            return None;
        }

        let op_code = b.drain_one();
        let method = op_code & 0x3F;
        match method {
            0x01..=0x05 | 0x08 | 0x10 => {
                // Method: Error Response (0x01)
                // Method: Exchange MTU Request (0x02)
                // Method: Exchange MTU Response (0x03)
                // Method: Find Information Request (0x04)
                // Method: Find Information Response (0x05)
                // Method: Read By Type Request (0x08)
                // Method: Read By Group Type Request (0x10)
                // TODO: Seem unimportant tough an implementation of these would be nice
                None
            }
            0x11 => {
                // Method: Read By Group Type Response (0x11)
                let length = b.drain_one() as usize;
                match length {
                    6 | 20 => {} // Ok
                    unknown_length => panic!("nr {}, unknown length {}", nr, unknown_length),
                };

                let mut attributes: Vec<AttributeGroupData> = Vec::new();
                while b.len() >= length {
                    let mut attribute_bytes = b.drain_bytes(length);
                    let handle = attribute_bytes.drain_u16_little_endian();
                    let group_end_handle = attribute_bytes.drain_u16_little_endian();
                    let uuid = UuidKind::from_bytes(attribute_bytes);

                    attributes.push(AttributeGroupData {
                        handle,
                        group_end_handle,
                        uuid,
                    });
                }

                Some(Self::ReadByGroupTypeResponse(attributes))
            }
            0x09 => {
                // Method: Read By Type Response (0x09)
                let length = b.drain_one() as usize;
                if length != 21 {
                    if length == 18 {
                        // dirty hack to detect device name responses
                        return None;
                    }
                    panic!("nr {}, unknown length {}", nr, length);
                }

                let mut attributes: Vec<AttributeData> = Vec::new();
                while b.len() >= length {
                    let mut attribute_bytes = b.drain_bytes(length);
                    let handle = attribute_bytes.drain_u16_little_endian();
                    let characteristic_properties = attribute_bytes.drain_one();
                    let characteristic_value_handle = attribute_bytes.drain_u16_little_endian();
                    let uuid = UuidKind::from_bytes(attribute_bytes);

                    attributes.push(AttributeData {
                        handle,
                        characteristic_properties,
                        characteristic_value_handle,
                        uuid,
                    });
                }

                Some(Self::ReadByTypeRespense(attributes))
            }
            0x0a => {
                // Method: Read Request (0x0a)
                assert!(b.len() == 2);

                let handle = b.drain_u16_little_endian();
                Some(Self::ReadRequest(handle))
            }
            0x0b => {
                // Method: Read Response (0x0b)
                let payload = b.vec().clone();
                Some(Self::ReadResponse(payload))
            }
            0x12 => {
                // Method: Write Request
                let handle = b.drain_u16_little_endian();
                let payload = b.vec().clone();
                Some(Self::WriteRequest(handle, payload))
            }
            0x13 => {
                // Method: Write Response
                let payload = b.vec().clone();
                Some(Self::WriteResponse(payload))
            }
            op_code => {
                println!("{}, unknown opcode method {:#04x}", nr, op_code);
                None
            }
        }
    }
}

pub enum UuidKind {
    Full(Vec<u8>),
    Short(Vec<u8>),
}

impl UuidKind {
    fn from_bytes(b: Bytes) -> Self {
        let uuid = b.0;
        if uuid.len() == 16 {
            Self::Full(uuid)
        } else {
            Self::Short(uuid)
        }
    }
    pub fn string(&self) -> String {
        let as_hex = self.hex();
        match self {
            Self::Short(_) => as_hex,
            Self::Full(_) => {
                let (a, remainder) = as_hex.split_at(8);
                let (b, remainder) = remainder.split_at(4);
                let (c, remainder) = remainder.split_at(4);
                let (d, remainder) = remainder.split_at(4);

                format!("{}-{}-{}-{}-{}", a, b, c, d, remainder)
            }
        }
    }
    pub fn hex(&self) -> String {
        let bytes = match self {
            Self::Full(bytes) | Self::Short(bytes) => bytes,
        };

        let mut response = String::new();
        for b in bytes {
            response = format!("{:02x}{}", b, response)
        }
        response
    }
}

pub struct AttributeGroupData {
    pub handle: u16,
    pub group_end_handle: u16,
    pub uuid: UuidKind,
}

pub struct AttributeData {
    pub handle: u16,
    pub characteristic_properties: u8,
    pub characteristic_value_handle: u16,
    pub uuid: UuidKind,
}
