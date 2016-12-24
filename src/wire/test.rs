use wire::msg::*;

#[test]
fn print_parse_dns_header() {
    let test = vec![0xc9, 0xba, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    println!("{:?}", parse_dns_header(&test));

}
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
//     let labels: Vec<&str> = parse_dns_name(&buffer[..]).unwrap().1;
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
//     let labels = parse_dns_name(&buffer[..]).unwrap().1;
//     let result = labels.join(".");
//     assert_eq!(result, "test.example.com")
// }
// 
// #[test]
// fn parse_query() {
//     let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//     0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
//     0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//     let q = parse_dns_query(&input[..]).unwrap().1;
//     println!("{:?}", q);
//     assert_eq!(q.names[0], "nic.cz")
// }
// 
// #[test]
// fn parse_query2() {
//     let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//     0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
//     0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//     let q = parse_dns_query2(&input[..]).unwrap();
//     println!("{:?}", q);
//     //assert_eq!(q.names[0], "nic.cz")
// }