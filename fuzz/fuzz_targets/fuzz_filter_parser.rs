#![no_main]

use crabdns_core::FilterEngine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let engine = FilterEngine::new(&[]);
        let _ = engine.reload_from_text(text);
        let _ = engine.evaluate("ads.example.com");
        if let Some(first_line) = text.lines().next() {
            let _ = engine.evaluate(first_line);
        }
    }
});
