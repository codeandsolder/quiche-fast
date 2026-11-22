#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

use quiche::h3::NameValue;

// Fuzzer for qpack codec. Checks that decode(encode(hdrs)) == hdrs. To get the
// initial hdrs, the fuzzer deserializes the input, and skips inputs where
// deserialization fails.
//
// The fuzzer could have been written to instead check encode(decode(input)) ==
// input. However, that transformation is not guaranteed to be the identify
// function, as there are multiple ways the same hdr list could be encoded.
fuzz_target!(|data: &[u8]| {
    let hdrs = match quiche::h3::qpack::decode(data, u64::MAX) {
        Err(_) => return,
        Ok(hdrs) => hdrs,
    };
    let encoded = quiche::h3::qpack::encode(&hdrs).unwrap();
    let decoded_hdrs = quiche::h3::qpack::decode(&encoded, u64::MAX).unwrap();

    let mut expected_hdrs = Vec::new();

    // Turn original headers into lower-case as the QPACK decode doesn't do
    // this.
    for h in &hdrs {
        let name = h.name().to_ascii_lowercase();

        expected_hdrs.push(quiche::h3::Header::new(&name, h.value()));
    }

    assert_eq!(expected_hdrs, decoded_hdrs)
});
