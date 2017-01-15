#[derive(Debug)]
pub enum Error {
    MalformedPacket,
    InsufficientLength,
    Other,
}