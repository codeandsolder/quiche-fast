// Copyright (C) 2021, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Proportional Rate Reduction
//!
//! This implementation is based on the following RFC:
//!
//! <https://datatracker.ietf.org/doc/html/rfc6937>

use std::cmp;

#[derive(Default, Debug)]
#[expect(
    clippy::upper_case_acronyms,
    reason = "PRR is the RFC 6937 algorithm name"
)]
pub struct PRR {
    // Total bytes delivered during recovery.
    prr_delivered: u64,

    // FlightSize at the start of recovery.
    recoverfs: usize,

    // Total bytes sent during recovery.
    prr_out: u64,

    // Total additional bytes can be sent for retransmit during recovery.
    pub snd_cnt: usize,
}

impl PRR {
    pub const fn on_packet_sent(&mut self, sent_bytes: usize) {
        self.prr_out = self.prr_out.saturating_add(sent_bytes as u64);

        self.snd_cnt = self.snd_cnt.saturating_sub(sent_bytes);
    }

    pub const fn congestion_event(&mut self, bytes_in_flight: usize) {
        self.prr_delivered = 0;

        self.recoverfs = bytes_in_flight;

        self.prr_out = 0;

        self.snd_cnt = 0;
    }

    pub fn on_packet_acked(
        &mut self, delivered_data: usize, pipe: usize, ssthresh: usize,
        max_datagram_size: usize,
    ) {
        self.prr_delivered =
            self.prr_delivered.saturating_add(delivered_data as u64);

        self.snd_cnt = if pipe > ssthresh {
            // Proportional Rate Reduction.
            if self.recoverfs > 0 {
                // The intermediate product can exceed the address width
                // even when the transmission allowance fits in a window.
                let allowed = if let Some(product) =
                    self.prr_delivered.checked_mul(ssthresh as u64)
                {
                    u128::from(product.div_ceil(self.recoverfs as u64))
                } else {
                    (u128::from(self.prr_delivered) * ssthresh as u128)
                        .div_ceil(self.recoverfs as u128)
                };
                usize::try_from(allowed.saturating_sub(u128::from(self.prr_out)))
                    .unwrap_or(usize::MAX)
            } else {
                0
            }
        } else {
            // PRR-SSRB.
            let limit = cmp::max(
                self.prr_delivered.saturating_sub(self.prr_out),
                delivered_data as u64,
            )
            .saturating_add(max_datagram_size as u64);

            // Attempt to catch up, as permitted by limit
            cmp::min(
                ssthresh - pipe,
                usize::try_from(limit).unwrap_or(usize::MAX),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_event() {
        let mut prr = PRR::default();
        let bytes_in_flight = 1000;

        prr.congestion_event(bytes_in_flight);

        assert_eq!(prr.recoverfs, bytes_in_flight);
        assert_eq!(prr.snd_cnt, 0);
    }

    #[test]
    fn on_packet_sent() {
        let mut prr = PRR::default();
        let bytes_in_flight = 1000;
        let bytes_sent = 500;

        prr.congestion_event(bytes_in_flight);

        prr.on_packet_sent(bytes_sent);

        assert_eq!(prr.prr_out, bytes_sent as u64);
        assert_eq!(prr.snd_cnt, 0);
    }

    #[test]
    fn on_packet_acked_prr() {
        let mut prr = PRR::default();
        let max_datagram_size = 1000;
        let bytes_in_flight = max_datagram_size * 10;
        let ssthresh = bytes_in_flight / 2;
        let acked = 1000;

        prr.congestion_event(bytes_in_flight);

        // pipe > ssthresh uses PRR algorithm.
        let pipe = bytes_in_flight;

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 500);

        let snd_cnt = prr.snd_cnt;

        // send one more allowed by snd_cnt
        prr.on_packet_sent(snd_cnt);

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 500);
    }

    #[test]
    fn proportional_allowance_does_not_overflow_intermediate_product() {
        let mut prr = PRR::default();
        // Just 256 KiB of delivered data and a 128 KiB threshold already
        // exceed a 32-bit intermediate product.
        let flight = 256 * 1024;
        let threshold = flight / 2;
        prr.congestion_event(flight);
        prr.on_packet_acked(flight, flight, threshold, 1200);
        assert_eq!(prr.snd_cnt, threshold);
        prr.on_packet_sent(threshold);
        prr.on_packet_acked(3, flight, threshold, 1200);
        assert_eq!(prr.snd_cnt, 2);
    }

    #[test]
    fn proportional_allowance_subtracts_sent_bytes_before_narrowing() {
        let mut prr = PRR::default();
        prr.congestion_event(2);
        prr.prr_delivered = u64::MAX - 4;
        prr.prr_out = u64::MAX - 7;
        prr.on_packet_acked(2, 4, 2, 1200);
        assert_eq!(prr.snd_cnt, 5);
    }

    #[test]
    fn ssrb_caps_allowance_without_wrapping() {
        let mut prr = PRR::default();
        prr.congestion_event(usize::MAX);
        prr.prr_delivered = u64::MAX - 1;
        prr.on_packet_acked(1, 1, usize::MAX, 1200);
        assert_eq!(prr.snd_cnt, usize::MAX - 1);
    }

    #[test]
    fn on_packet_acked_prr_overflow() {
        let mut prr = PRR::default();
        let max_datagram_size = 1000;
        let bytes_in_flight = max_datagram_size * 10;
        let ssthresh = bytes_in_flight / 2;
        let acked = 1000;

        prr.congestion_event(bytes_in_flight);

        prr.on_packet_sent(max_datagram_size);

        // pipe > ssthresh uses PRR algorithm.
        let pipe = bytes_in_flight + max_datagram_size;

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 0);
    }

    #[test]
    fn on_packet_acked_prr_zero_in_flight() {
        let mut prr = PRR::default();
        let max_datagram_size = 1000;
        let bytes_in_flight = 0;
        let ssthresh = 3000;
        let acked = 1000;

        prr.congestion_event(bytes_in_flight);

        // pipe > ssthresh uses PRR algorithm.
        let pipe = ssthresh + 1000;

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 0);
    }

    #[test]
    fn on_packet_acked_prr_ssrb() {
        let mut prr = PRR::default();
        let max_datagram_size = 1000;
        let bytes_in_flight = max_datagram_size * 10;
        let ssthresh = bytes_in_flight / 2;
        let acked = 1000;

        prr.congestion_event(bytes_in_flight);

        // pipe <= ssthresh uses PRR-SSRB algorithm.
        let pipe = max_datagram_size;

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 2000);

        let snd_cnt = prr.snd_cnt;

        // send one more allowed by snd_cnt
        prr.on_packet_sent(snd_cnt);

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 2000);
    }

    #[test]
    fn on_packet_acked_prr_ssrb_overflow() {
        let mut prr = PRR::default();
        let max_datagram_size = 1000;
        let bytes_in_flight = max_datagram_size * 10;
        let ssthresh = bytes_in_flight / 2;
        let acked = 500;

        prr.congestion_event(bytes_in_flight);

        // pipe <= ssthresh uses PRR-SSRB algorithm.
        let pipe = max_datagram_size;

        prr.on_packet_sent(max_datagram_size);

        prr.on_packet_acked(acked, pipe, ssthresh, max_datagram_size);

        assert_eq!(prr.snd_cnt, 1500);
    }
}
