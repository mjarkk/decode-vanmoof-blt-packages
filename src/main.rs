mod analyzer;
pub mod human;
pub mod parser;

use analyzer::analyze;
use parser::{BltPacket, BltPacketKind};
use std::{fs::File, io::Read};

struct Args {
    file: String,
    encryption_key: Option<String>,
    bike_id: Option<String>,
    hide_challenges: bool,
    show_only_first_part_of_uuid: bool,
}

fn main() {
    let args = Args {
        file: String::from("bt_snoop.log"),
        encryption_key: None,
        bike_id: None,
        hide_challenges: false,
        show_only_first_part_of_uuid: false,
    };

    let mut log_file = File::open(args.file).expect("Error opening logfile");

    let mut contents: Vec<u8> = Vec::new();
    log_file
        .read_to_end(&mut contents)
        .expect("Error reading file");

    if !contents
        .drain(..8)
        .eq(vec![0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00])
    {
        panic!("not a btl snoop file");
    }
    let mut content_bytes = parser::Bytes::new(contents);

    let version_number = content_bytes.drain_u32_big_endian();
    if version_number != 1 {
        panic!("only blt snoop version 1 is supported, got {version_number}")
    }

    let data_link_type = content_bytes.drain_u32_big_endian();
    match data_link_type {
        1001 => {} // Expected
        1002 => panic!("Unsupported Datalink Type: HCI UART (H4)"),
        1003 => panic!("Unsupported Datalink Type: HCI BSCP"),
        1004 => panic!("Unsupported Datalink Type: HCI Serial (H5)"),
        1005 => panic!("Unsupported Datalink Type: Unassigned"),
        data_link_type => {
            panic!("Unsupported Datalink Type: Reserved / Unassigned ({data_link_type})")
        }
    }

    // Firstly lets parse the packages
    let mut nr: usize = 0;
    let mut packages: Vec<BltPacket> = Vec::new();
    let mut parser = parser::Parser::new();
    loop {
        if content_bytes.len() == 0 {
            break;
        }

        nr += 1;

        let original_len = content_bytes.drain_u32_big_endian() as usize;
        let included_len = content_bytes.drain_u32_big_endian() as usize;
        content_bytes.drain_u32_big_endian(); // packet_record_len
        content_bytes.drain_u32_big_endian(); // comulative_drops
        content_bytes.drain_u32_big_endian(); // timestap_seconds
        content_bytes.drain_u32_big_endian(); // timestap_microseconds

        let packet_data = content_bytes.drain_bytes(included_len);
        if packet_data.len() > 0 {
            let parsed_packet = parser.parse(packet_data, nr);
            if let Some(packet) = parsed_packet {
                packages.push(packet);
            }
        }

        let padd_size = original_len - included_len;
        if padd_size > 0 {
            content_bytes.drain(padd_size);
        }
    }

    let parsed_packages = analyze(packages);
    for package in parsed_packages {
        println!("#{} {}", package.nr, package.content.human());
    }
}
