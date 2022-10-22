use super::{Att, Bytes, Parser};

pub fn parse_blt_hci_acl(p: &mut Parser, b: &mut Bytes, handle: u16, nr: usize) -> Option<Att> {
    let part_data_len = b.drain_u16_little_endian();
    let mut part_data = b.drain_vec(part_data_len);

    println!("nr: {}", nr);

    let (data, attribute_protocol) = if let Some(continueing_fragment) = &mut p.continueing_fragment
    {
        continueing_fragment.data.append(&mut part_data);
        if continueing_fragment.data.len() < continueing_fragment.total_len {
            return None;
        } else if continueing_fragment.data.len() > continueing_fragment.total_len {
            panic!(
                "a blt hci alc continueing fragment package should not overflow, packet nr: {}",
                nr
            );
        }
        let resp = continueing_fragment.clone();
        p.continueing_fragment = None;
        (resp.data, resp.attribute_protocol)
    } else {
        let data_len = b.drain_u16_little_endian() as usize;
        let attribute_protocol = b.drain_u16_little_endian();
        if part_data.len() < data_len {
            // Expect a Continueing Fragment
            p.continueing_fragment = Some(BltHciAclContinueingFragment {
                _handle: handle,
                total_len: data_len,
                data: part_data,
                attribute_protocol,
            });
            return None;
        }
        (part_data, attribute_protocol)
    };

    Att::parse(&mut Bytes::new(data), attribute_protocol, nr)
}

#[derive(Clone)]
pub struct BltHciAclContinueingFragment {
    _handle: u16,
    attribute_protocol: u16,
    total_len: usize,
    data: Vec<u8>,
}
