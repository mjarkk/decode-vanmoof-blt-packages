use super::Bytes;

pub enum BltEventMeta {
    AdvertizingReport(BltEventAdvertizingReport),
    EnhancedConnectionComplete(BltEventEnhancedConnectionComplete),
    UnknownSubEvent(u8),
}

pub struct BltEventAdvertizingReport {
    address: Vec<u8>,
    device_name: BltEventAdvertizingReportName,
}

pub enum BltEventAdvertizingReportName {
    Shortened(String),
    Complete(String),
}

impl BltEventMeta {
    pub fn parse(b: &mut Bytes, nr: usize) -> Option<Self> {
        b.drain_one(); // parameter_total_len
        let sub_event = b.drain_one();
        match sub_event {
            0x02 => {
                // Sub Event: LE Advertizing report (0x02)

                b.drain_one(); // num_reports
                let event_type = b.drain_one();
                b.drain_one(); // address_type
                let address = b.drain_vec(6u8);

                let data_len = b.drain_one();
                if data_len == 0 {
                    return None;
                }

                let (has_flags, supported) = match event_type {
                    // Event Type: Connectable Undirected Advertising (0x00)
                    // Event Type: Unknown (0x20)
                    // Event Type: Unknown (0x10)
                    // Event Type: Unknown (0x60)
                    0x00 | 0x10 | 0x20 | 0x60 => (true, true),
                    // Event Type: Scan Response (0x04)
                    // Event Type: Unknown (0x13)
                    // Event Type: Unknown (0x14)
                    // Event Type: Unknown (0x24)
                    0x04 | 0x13 | 0x014 | 0x24 => (false, true),
                    // Event Type: Unknown (0x12)
                    // Event Type: Unknown (0x22)
                    // Event Type: Unknown (0x23)
                    // These events come up in blt sniffs but are never send by vanmoof bikes (seems like)
                    0x12 | 0x22 | 0x23 => (false, false),
                    // Event Type: Non-Connectable Undirected Advertising (0x03)
                    // Event Type: Scannable Undirected Advertising (0x02)
                    // These event seem to come from devices that can't be connected to
                    0x02 | 0x03 => (false, false),
                    et => {
                        println!("#{} Unknown advertising event type: {:x}", nr, et);
                        (false, false)
                    }
                };

                if !supported {
                    return None;
                }

                if has_flags {
                    let flags_len = b.drain_one();
                    b.drain(flags_len);
                }

                let device_name_len = b.drain_one();
                let device_name_type = b.drain_one();
                let device_name_string =
                    String::from_utf8_lossy(&b.drain_vec(device_name_len - 1)).to_string();

                match device_name_type {
                    0x08 => Some(BltEventAdvertizingReportName::Shortened(device_name_string)),
                    0x09 => Some(BltEventAdvertizingReportName::Complete(device_name_string)),
                    _ => None,
                }
                .map(|device_name| {
                    Self::AdvertizingReport(BltEventAdvertizingReport {
                        address,
                        device_name,
                    })
                })
            }
            0x0a => {
                // Sub Event: LE Enhanced Connection Complete (0x0a)
                BltEventEnhancedConnectionComplete::parse(b, nr)
                    .map(|e| Self::EnhancedConnectionComplete(e))
            }
            0x04 | 0x06 | 0x03 => {
                // Sub Event: LE Connection Update Complete (0x03)
                // Sub Event: LE Read Remote Features Complete (0x04)
                // Sub Event: LE Remote Connection Parameter Request (0x06)
                // These sub commands do not contain any vauluable information
                None
            }
            _ => Some(Self::UnknownSubEvent(sub_event)),
        }
    }
}

pub struct BltEventEnhancedConnectionComplete {
    address: Vec<u8>,
    connection_handle: u32,
}

impl BltEventEnhancedConnectionComplete {
    fn parse(b: &mut Bytes, _nr: usize) -> Option<Self> {
        // Sub Event: LE Enhanced Connection Complete (0x0a)

        b.drain(5u8);
        let address = b.drain_vec(6u8);

        let connection_handle = b.drain_u32_little_endian();
        Some(Self {
            address,
            connection_handle,
        })
    }
}
