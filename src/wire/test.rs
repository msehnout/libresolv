use super::msg;
use message::Header;

#[test]
fn test_parse_dns_header() {
    let test = vec![0xc9, 0xba, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let test: Header = msg::parse_dns_header(&test).unwrap().1;
    // TODO: test all parameters
    assert_eq!(test.id, 0xc9ba);
    assert_eq!(test.response, false);
    assert_eq!(test.tc, false);
    assert_eq!(test.rd, true);
    assert_eq!(test.qdcount, 1);
    assert_eq!(test.ancount, 0);
    assert_eq!(test.nscount, 0);
    assert_eq!(test.arcount, 1);

}

#[test]
fn test_parse_dns_name_label() {
    let input = b"\x05abcde";
    let output = msg::parse_dns_name_label(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Label("abcde".to_string()));
}

#[test]
fn test_parse_dns_name_pointer() {
    let input = b"\xc0\x0c";
    let output = msg::parse_dns_name_pointer(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x0c));
}

#[test]
fn test_parse_dns_name_unit() {
    let input = b"\xf2\x35";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x3235));
    let input = b"\x08abcde123";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Label("abcde123".to_string()));
}

#[test]
fn test_parse_dns_name_bottom() {
    let input = b"\x00\xf2\x35";
    let output = msg::parse_dns_name_bottom(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::End);
    let input = b"\xf2\x35";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x3235));
}

#[test]
fn test_parse_dns_name() {
    let input = b"\x05abcde\x04abcd\x03abc\x00";
    let output = msg::parse_dns_name(&input[..]).unwrap().1;
    assert_eq!(output, vec![
    msg::NameUnit::Label(String::from("abcde")),
    msg::NameUnit::Label(String::from("abcd")),
    msg::NameUnit::Label(String::from("abc")),
    msg::NameUnit::End,
    ]);
    let input = b"\x05abcde\xc0\x01";
    let output = msg::parse_dns_name(&input[..]).unwrap().1;
    assert_eq!(output, vec![
    msg::NameUnit::Label(String::from("abcde")),
    msg::NameUnit::Pointer(1),
    ]);
}

#[test]
fn test_parse_query() {
    let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let q = msg::parse_dns_message(&input[..]).unwrap().1;
    println!("{:?}", q);
    assert_eq!(q.queries[0].name, vec![
    msg::NameUnit::Label(String::from("nic")),
    msg::NameUnit::Label(String::from("cz")),
    msg::NameUnit::End,
    ]);
}

// #[test]
// fn test_parse_query() {
//     let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//     0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
//     0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//     let q = msg::parse_dns_query(&input[..]).unwrap().1;
//     println!("{:?}", q);
//     assert_eq!(q.names[0], "nic.cz")
// }
//
// #[test]
// fn parse_name_simple() {
//     let name = "test.example.com.";
//     let mut buffer = Vec::new();
//     let labels: Vec<&str> = name.split_terminator('.').collect();
//     for label in labels {
//         let len = label.len() as u8;
//         buffer.push(len);
//         buffer.extend(label.as_bytes().iter().cloned());
//     }
//     buffer.push(0);
//
//     // TODO: Parse the name in wire format
//     let labels: Vec<&str> = msg::parse_dns_name(&buffer[..]).unwrap().1;
//     // POZOR: na konci je prazdny label
//     let result = labels.join(".");
//     assert_eq!(result, "test.example.com")
// }
//
// #[test]
// fn parse_name_2() {
//     let name = "test.example.com.";
//     let mut buffer = Vec::new();
//     let labels: Vec<&str> = name.split_terminator('.').collect();
//     for label in labels {
//         let len = label.len() as u8;
//         buffer.push(len);
//         buffer.extend(label.as_bytes().iter().cloned());
//     }
//     buffer.push(0);
//     buffer.push(5);
//     buffer.extend(b"abcde");
//     buffer.push(0);
//
//     let labels = msg::parse_dns_name(&buffer[..]).unwrap().1;
//     let result = labels.join(".");
//     assert_eq!(result, "test.example.com")
// }
//

// #[test]
// fn parse_query2() {
//     let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//     0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
//     0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//     let q = msg::parse_dns_query2(&input[..]).unwrap();
//     println!("{:?}", q);
//     //assert_eq!(q.names[0], "nic.cz")
// }
