//! Every parser that takes bytes from the network.
#![no_main]

use libfuzzer_sys::fuzz_target;
use provider_testonly::TestOnlyProvider;
use qalqon_core::control::{ControlMessage, parse_channel_options, parse_grants};
use qalqon_core::crl::Crl;
use qalqon_core::crypto::PublicKey;
use qalqon_core::frag::Reassembler;
use qalqon_core::wire::{self, FrameDecoder};

fuzz_target!(|data: &[u8]| {
    let p = TestOnlyProvider::new();
    if let Ok((header, body)) = wire::parse_frame(data) {
        let mut r = Reassembler::new();
        let _ = r.push(&header, body);
    }
    let _ = wire::parse_extensions(data);
    let _ = qalqon_core::cert::parse_many(&p, data);
    if let Ok(message) = ControlMessage::decode(data) {
        let _ = message.encode();
    }
    let _ = parse_grants(data);
    let _ = parse_channel_options(data);
    let _ = qalqon_core::relay::parse_join(data);
    let key = PublicKey { algorithm: 0xFF01, key: vec![1; 32] };
    let _ = Crl::verify(&p, &key, data);
    let mut decoder = FrameDecoder::new();
    decoder.push(data);
    while let Ok(Some(_)) = decoder.next_frame() {}
});
