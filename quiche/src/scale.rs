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

/// Rounding policy for a nonnegative integer multiplied by a floating-point
/// gain. Nearest breaks ties upward, matching the prior positive `f64::round`.
#[derive(Clone, Copy)]
pub(super) enum Rounding {
    Down,
    Up,
    Nearest,
}

/// Scales a full-width integer by the exact value represented by a binary64
/// gain, without first rounding the integer to floating point. Negative and
/// NaN gains produce zero; positive overflow saturates. Zero times infinity
/// produces zero, as with a saturating float-to-integer conversion.
///
/// A finite f64 is an integer significand times a power of two. Multiplying
/// its at-most-53-bit significand by a u64 needs at most 117 bits. Shifting
/// that product gives the integer result, with a single final rounding step.
#[inline]
pub(super) fn scale_u64(value: u64, gain: f64, rounding: Rounding) -> u64 {
    u64::try_from(scale_wide(value, gain, rounding)).unwrap_or(u64::MAX)
}

/// Scale into a wide accumulator, rounding once from the exact binary64
/// significand product. In particular the integer input never passes through
/// a floating-point conversion.
#[inline]
pub(super) fn scale_wide(value: u64, gain: f64, rounding: Rounding) -> u128 {
    if value == 0 || gain.is_nan() || gain <= 0.0 {
        return 0;
    }
    if gain.to_bits() == 1.0_f64.to_bits() {
        return u128::from(value);
    }
    if gain.is_infinite() {
        return u128::MAX;
    }

    let (product, exponent) = gain_product(value, gain);

    if exponent >= 0 {
        let shift = exponent.unsigned_abs();
        if shift > product.leading_zeros() {
            return u128::MAX;
        }
        return product << shift;
    }

    let shift = exponent.unsigned_abs();
    if shift >= u128::BITS {
        // A positive product of at most 117 bits is below half of 2^128.
        return u128::from(matches!(rounding, Rounding::Up));
    }

    let quotient = product >> shift;
    let remainder = product - (quotient << shift);
    let increment = match rounding {
        Rounding::Down => false,
        Rounding::Up => remainder != 0,
        Rounding::Nearest => remainder >= (1_u128 << (shift - 1)),
    };
    quotient + u128::from(increment)
}

/// Exact significand product and binary exponent for a positive finite gain.
#[inline]
fn gain_product(value: u64, gain: f64) -> (u128, i32) {
    const FRACTION_BITS: u32 = 52;
    const EXPONENT_BIAS: i32 = 1023;
    const SIGNIFICAND_BIT: u64 = 1 << FRACTION_BITS;
    let bits = gain.to_bits();
    let encoded_exponent =
        i32::try_from((bits >> FRACTION_BITS) & 0x7ff).unwrap_or(0);
    let fraction = bits & (SIGNIFICAND_BIT - 1);
    let (significand, encoded_exponent) = if encoded_exponent == 0 {
        (fraction, 1) // subnormals have no implicit leading bit
    } else {
        (fraction | SIGNIFICAND_BIT, encoded_exponent)
    };
    let product = u128::from(value) * u128::from(significand);
    (product, encoded_exponent - EXPONENT_BIAS - 52)
}

/// Floor an integer times a binary64 gain divided by an integer, saturating
/// only the final quotient. This avoids both a rounded floating-point divisor
/// and premature saturation of an intermediate product.
#[inline]
pub(super) fn scale_gain_div_u64(value: u64, gain: f64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    // Even if the wide numerator saturated, its quotient by any nonzero
    // u64 divisor must still be at least u64::MAX. Flooring before the
    // integer division does not change the final floor.
    u64::try_from(scale_wide(value, gain, Rounding::Down) / u128::from(divisor))
        .unwrap_or(u64::MAX)
}

#[inline]
pub(super) fn scale_usize(value: usize, gain: f64, rounding: Rounding) -> usize {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    usize::try_from(scale_u64(value, gain, rounding)).unwrap_or(usize::MAX)
}

/// Scale by an exact nonnegative rational. Round only once, after the
/// full-width multiplication; never round the input or the ratio to a float.
/// A zero denominator represents an unavailable ratio and yields zero.
#[inline]
pub(super) fn scale_ratio_u64(
    value: u64, numerator: u64, denominator: u64, rounding: Rounding,
) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let product = u128::from(value) * u128::from(numerator);
    let denominator = u128::from(denominator);
    let quotient = product / denominator;
    let remainder = product % denominator;
    let increment = match rounding {
        Rounding::Down => false,
        Rounding::Up => remainder != 0,
        Rounding::Nearest => remainder >= denominator.div_ceil(2),
    };
    u64::try_from(quotient + u128::from(increment)).unwrap_or(u64::MAX)
}

#[inline]
pub(super) fn scale_ratio_usize(
    value: usize, numerator: u64, denominator: u64, rounding: Rounding,
) -> usize {
    usize::try_from(scale_ratio_u64(
        u64::try_from(value).unwrap_or(u64::MAX),
        numerator,
        denominator,
        rounding,
    ))
    .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::scale_gain_div_u64;
    use super::scale_ratio_u64;
    use super::scale_ratio_usize;
    use super::scale_u64;
    use super::scale_usize;
    use super::Rounding;

    #[test]
    fn wide_scaling_preserves_full_significand_product() {
        use super::scale_wide;

        for value in [0, 1, 1_u64 << 53, u64::MAX] {
            assert_eq!(
                scale_wide(value, 4_294_967_296.0, Rounding::Down),
                u128::from(value) << 32
            );
            assert_eq!(
                scale_wide(value, 1.5, Rounding::Down),
                u128::from(value) * 3 / 2
            );
        }
        assert_eq!(
            scale_wide(1, 2.0_f64.powi(127), Rounding::Down),
            1_u128 << 127
        );
        assert_eq!(scale_wide(2, 2.0_f64.powi(127), Rounding::Down), u128::MAX);
        assert_eq!(scale_wide(u64::MAX, f64::INFINITY, Rounding::Up), u128::MAX);
        assert_eq!(scale_wide(1, f64::from_bits(1), Rounding::Up), 1);
    }

    #[test]
    fn gain_division_rounds_once_and_saturates_only_after_division() {
        for value in [0, 1, 1299, 1300, 1301, (1 << 53) + 1, u64::MAX] {
            for divisor in [1, 2, 1300, u64::MAX] {
                for (gain, num, den) in [
                    (0.25, 1, 4),
                    (0.5, 1, 2),
                    (1.0, 1, 1),
                    (1.5, 3, 2),
                    (8.0, 8, 1),
                ] {
                    let exact =
                        u128::from(value) * num / (u128::from(divisor) * den);
                    assert_eq!(
                        scale_gain_div_u64(value, gain, divisor),
                        u64::try_from(exact).unwrap_or(u64::MAX)
                    );
                }
            }
        }
        assert_eq!(scale_gain_div_u64(u64::MAX, 2.0, 2), u64::MAX);
        assert_eq!(scale_gain_div_u64(u64::MAX, 2.0, 4), u64::MAX / 2);
        assert_eq!(scale_gain_div_u64(1, f64::MAX, u64::MAX), u64::MAX);
        assert_eq!(scale_gain_div_u64(u64::MAX, f64::from_bits(1), 2), 0);
        assert_eq!(scale_gain_div_u64(123, 1.0, 0), 0);
        assert_eq!(scale_gain_div_u64(0, f64::INFINITY, 2), 0);
    }

    #[test]
    fn rational_scaling_preserves_integer_loss_and_rounding() {
        for value in [0, 1, 7, 10, 11, (1 << 53) + 1, u64::MAX] {
            let product = u128::from(value) * 7;
            for (rounding, expected) in [
                (Rounding::Down, product / 10),
                (Rounding::Up, product.div_ceil(10)),
                (Rounding::Nearest, (product + 5) / 10),
            ] {
                assert_eq!(
                    scale_ratio_u64(value, 7, 10, rounding),
                    u64::try_from(expected).unwrap()
                );
            }
            assert_eq!(
                scale_ratio_u64(value, u64::MAX, u64::MAX, Rounding::Nearest),
                value
            );
        }
        assert_eq!(scale_ratio_u64(10, 1, 0, Rounding::Nearest), 0);
        assert_eq!(
            scale_ratio_u64(u64::MAX, u64::MAX, 1, Rounding::Up),
            u64::MAX
        );
        assert_eq!(
            scale_ratio_usize(usize::MAX, 7, 10, Rounding::Down),
            usize::try_from((usize::MAX as u128) * 7 / 10).unwrap()
        );
    }

    #[test]
    fn exact_integer_scaling_at_precision_boundaries() {
        let large = (1_u64 << 53) + 1;
        for (rounding, half) in [
            (Rounding::Down, large / 2),
            (Rounding::Up, large.div_ceil(2)),
            (Rounding::Nearest, large.div_ceil(2)),
        ] {
            assert_eq!(scale_u64(large, 1.0, rounding), large);
            assert_eq!(scale_u64(large, 0.5, rounding), half);
            assert_eq!(scale_u64(large, 2.0, rounding), large * 2);
            assert_eq!(scale_u64(u64::MAX, 1.0, rounding), u64::MAX);
            assert_eq!(scale_u64(u64::MAX, 2.0, rounding), u64::MAX);
            assert_eq!(scale_u64(0, f64::INFINITY, rounding), 0);
            assert_eq!(scale_u64(large, f64::INFINITY, rounding), u64::MAX);
            assert_eq!(scale_u64(large, f64::NAN, rounding), 0);
            assert_eq!(scale_u64(large, -1.0, rounding), 0);
        }
    }

    #[test]
    fn fractional_scaling_rounds_once_and_saturates() {
        let tiny = f64::from_bits(1);
        assert_eq!(scale_u64(u64::MAX, tiny, Rounding::Up), 1);
        assert_eq!(scale_u64(u64::MAX, tiny, Rounding::Nearest), 0);
        assert_eq!(scale_u64(u64::MAX, tiny, Rounding::Down), 0);
        assert_eq!(scale_u64(u64::MAX, 0.5, Rounding::Down), u64::MAX / 2);
        assert_eq!(scale_u64(u64::MAX, 0.5, Rounding::Nearest), 1 << 63);
        assert_eq!(scale_u64(7, 1.25, Rounding::Down), 8);
        assert_eq!(scale_u64(7, 1.25, Rounding::Up), 9);
        assert_eq!(scale_u64(7, 1.25, Rounding::Nearest), 9);
        assert_eq!(scale_u64(1, 2.0_f64.powi(64), Rounding::Down), u64::MAX);
        assert_eq!(scale_u64(1, 2.0_f64.powi(63), Rounding::Up), 1 << 63);
        assert_eq!(scale_usize(usize::MAX, 1.0, Rounding::Up), usize::MAX);
        assert_eq!(scale_usize(usize::MAX, 2.0, Rounding::Down), usize::MAX);
    }

    #[test]
    fn dyadic_gains_match_wide_integer_reference() {
        // Independently evaluate a set of dyadic factors as rational numbers,
        // including full-width inputs and values whose f64 conversion loses
        // bits. No floating-point intermediate is used by the oracle.
        for value in [0, 1, 7, 65535, 1 << 24, (1 << 53) + 1, u64::MAX] {
            for numerator in [1_u32, 3, 7, 17, 255, 65535] {
                for exponent in [0_u32, 1, 4, 16, 31] {
                    let denominator = 1_u64 << exponent;
                    let gain = f64::from(numerator) /
                        2.0_f64.powi(i32::try_from(exponent).unwrap());
                    let product = u128::from(value) * u128::from(numerator);
                    let denominator = u128::from(denominator);
                    for (rounding, expected) in [
                        (Rounding::Down, product / denominator),
                        (Rounding::Up, product.div_ceil(denominator)),
                        (
                            Rounding::Nearest,
                            (product + denominator / 2) / denominator,
                        ),
                    ] {
                        assert_eq!(
                            scale_u64(value, gain, rounding),
                            u64::try_from(expected).unwrap_or(u64::MAX)
                        );
                    }
                }
            }
        }
    }
}
