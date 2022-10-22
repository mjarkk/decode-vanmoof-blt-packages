use super::Bytes;

pub enum Att {
    ReadByGroupTypeResponse(Vec<AttributeGroupData>),
    ReadByTypeResponse(Vec<AttributeData>),
}

impl Att {
    pub fn parse(b: &mut Bytes, attribute_protocol: u16, nr: usize) -> Option<Self> {
        if attribute_protocol != 0x0004 {
            return None;
        }

        let op_code = b.drain_one();
        match op_code {
            0x01 | 0x03 => {
                // Opcode: Exchange MTU Response (0x03)
                // Opcode: Error Response (0x01)
                // Ignore
                None
            }
            0x11 => {
                // Opcode: Read By Group Type Response (0x11)
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
                // Opcode: Read By Type Response (0x09)
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

                Some(Self::ReadByTypeResponse(attributes))
            }
            op_code => {
                println!("{}, unknown opcode {:#04x}", nr, op_code);
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
}

pub struct AttributeGroupData {
    handle: u16,
    group_end_handle: u16,
    uuid: UuidKind,
}

pub struct AttributeData {
    handle: u16,
    characteristic_properties: u8,
    characteristic_value_handle: u16,
    uuid: UuidKind,
}
