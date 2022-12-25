use super::human;
use super::parser;

use parser::att::RawAtt;
use parser::{BltPacket, BltPacketKind};
use std::collections::HashMap;

pub struct ParsedAttRequest {
    pub nr: usize,
    pub content: ParsedAttRequestContent,
}

pub enum ParsedAttRequestContent {
    Read(AttRead),
    Write(AttWrite),
}

impl ParsedAttRequestContent {
    pub fn human(&self) -> String {
        match self {
            Self::Read(data) => format!(
                "Read {} > [{}]",
                data.human_handle,
                human::human_u8_list(&data.response_payload),
            ),
            Self::Write(data) => {
                format!(
                    "Write {} > [{}]",
                    data.human_handle,
                    human::human_u8_list(&data.request_payload)
                )
            }
        }
    }
}

pub struct AttRead {
    pub human_handle: String,
    pub response_payload: Vec<u8>,
}
pub struct AttWrite {
    pub human_handle: String,
    pub request_payload: Vec<u8>,
    pub response_payload: Vec<u8>,
}

struct AnalyzeState {
    last_read_request: Option<u16>,
    last_write_reques: Option<(u16, Vec<u8>)>,
    attributes: HashMap<u16, String>,
}

impl AnalyzeState {
    fn human_att(&self, u: &u16) -> String {
        if let Some(att) = self.attributes.get(u) {
            att.clone()
        } else {
            format!("(Unknown att({:#06x}))", u)
        }
    }
}

pub fn analyze(packages: Vec<BltPacket>) -> Vec<ParsedAttRequest> {
    let mut state = AnalyzeState {
        last_read_request: None,
        last_write_reques: None,
        attributes: HashMap::new(),
    };

    let mut att_requests: Vec<ParsedAttRequest> = Vec::new();

    // 1. Analyze the meta data provided by the att reques
    for pkg in packages.iter() {
        match &pkg.kind {
            BltPacketKind::RawAtt(ev) => match ev {
                RawAtt::ReadByGroupTypeResponse(attribute_group_data) => {
                    for group in attribute_group_data {
                        state.attributes.insert(group.handle, group.uuid.string());
                    }
                }
                RawAtt::ReadByTypeRespense(attribute_data) => {
                    for entry in attribute_data {
                        state.attributes.insert(entry.handle, entry.uuid.string());
                    }
                }
                // Will parse later
                RawAtt::ReadRequest(_) | RawAtt::ReadResponse(_) => {}
                RawAtt::WriteRequest(_, _) | RawAtt::WriteResponse(_) => {}
            },
            BltPacketKind::MetaEvent(_) => {
                // FIXME implement me!
            }
        };
    }

    let mut keys: Vec<String> = Vec::new();
    for key in state.attributes.keys() {
        keys.push(format!("{:#06x}", key));
    }

    println!("{}", keys.join(", "));

    // 2. Analyze the actual read / write att packages
    for pkg in packages.iter() {
        let mut parsed_content: Option<ParsedAttRequestContent> = None;
        match &pkg.kind {
            BltPacketKind::RawAtt(ev) => match ev {
                RawAtt::ReadRequest(handle) => {
                    state.last_read_request = Some(handle.clone());
                }
                RawAtt::ReadResponse(payload) => {
                    if let Some(handle) = state.last_read_request {
                        parsed_content = Some(ParsedAttRequestContent::Read(AttRead {
                            human_handle: state.human_att(&handle),
                            response_payload: payload.clone(),
                        }));
                        state.last_read_request = None;
                    } else {
                        println!("Nr: {}, dangeling Read response without request", pkg.nr)
                    }
                }
                RawAtt::WriteRequest(handle, payload) => {
                    state.last_write_reques = Some((handle.clone(), payload.clone()));
                }
                RawAtt::WriteResponse(response_payload) => {
                    if let Some((handle, request_payload)) = &state.last_write_reques {
                        parsed_content = Some(ParsedAttRequestContent::Write(AttWrite {
                            human_handle: state.human_att(handle),
                            request_payload: request_payload.clone(),
                            response_payload: response_payload.clone(),
                        }));
                        state.last_write_reques = None;
                    } else {
                        println!("Nr: {}, dangeling Write response without request", pkg.nr)
                    }
                }
                // Parsed earlier
                RawAtt::ReadByGroupTypeResponse(_) => {}
                RawAtt::ReadByTypeRespense(_) => {}
            },
            BltPacketKind::MetaEvent(_) => {
                // FIXME implement me!
            }
        };

        // Check if the content was parsed thus important to show to the user
        if let Some(content) = parsed_content {
            att_requests.push(ParsedAttRequest {
                nr: pkg.nr,
                content: content,
            });
        }
    }

    if state.last_read_request.is_some() {
        println!("Unhandled read request");
    }
    if state.last_write_reques.is_some() {
        println!("Unhandled write request");
    }

    att_requests
}
