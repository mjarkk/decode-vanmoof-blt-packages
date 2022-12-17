use super::{Bytes, Parser, RawAtt};

pub fn parse_blt_hci_acl(p: &mut Parser, b: &mut Bytes, handle: u16, nr: usize) -> Option<RawAtt> {
    let part_data_len = b.drain_u16_little_endian();

    let continueing_fragment = p.continueing_fragment_for_conn_handle.get_mut(&handle);

    let (data, attribute_protocol, clear_handle) = if let Some(continue_frag) = continueing_fragment
    {
        let mut part_data = b.drain_vec(part_data_len);
        continue_frag.data.append(&mut part_data);

        if continue_frag.data.len() < continue_frag.total_len {
            return None;
        } else if continue_frag.data.len() > continue_frag.total_len {
            panic!(
                "a blt hci alc continueing fragment package should not overflow, packet nr: {}",
                nr
            );
        }

        let resp = continue_frag.clone();
        (resp.data, resp.attribute_protocol, true)
    } else {
        let data_len = b.drain_u16_little_endian() as usize;
        let attribute_protocol = b.drain_u16_little_endian();
        let part_data = b.drain_vec(part_data_len - 4);

        if part_data.len() < data_len {
            // Expect a Continueing Fragment
            let continueing_fragment = BltHciAclContinueingFragment {
                total_len: data_len,
                data: part_data,
                attribute_protocol,
            };

            p.continueing_fragment_for_conn_handle
                .insert(handle, continueing_fragment);

            return None;
        }
        (part_data, attribute_protocol, false)
    };

    if clear_handle {
        p.continueing_fragment_for_conn_handle.remove(&handle);
    }

    RawAtt::parse(&mut Bytes::new(data), attribute_protocol, nr)
}

#[derive(Clone)]
pub struct BltHciAclContinueingFragment {
    attribute_protocol: u16,
    total_len: usize,
    data: Vec<u8>,
}
