#![no_main]

use crabdns_core::cache::patch_tx_id;
use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut copy = data.to_vec();
    patch_tx_id(&mut copy, 0x1234);
    let _ = Message::from_vec(&copy);
});
