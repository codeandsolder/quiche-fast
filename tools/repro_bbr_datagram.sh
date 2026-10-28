#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 [--target-dir DIR]" >&2
    exit 2
}

target_dir=""
while (($#)); do
    case "$1" in
        --target-dir)
            (($# >= 2)) || usage
            target_dir=$2
            shift 2
            ;;
        -h|--help)
            echo "usage: $0 [--target-dir DIR]"
            exit 0
            ;;
        *)
            usage
            ;;
    esac
done

command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
command -v tar >/dev/null || { echo "tar is required" >&2; exit 2; }
command -v perl >/dev/null || { echo "perl is required" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp="$(mktemp -d "${TMPDIR:-/tmp}/quiche-bbr-repro.XXXXXX")"
trap 'rm -rf -- "$temp"' EXIT

checkout="$temp/source"
mkdir -p "$checkout"
(
    cd "$root"
    git ls-files -z | tar --null -T - -cf -
) | (
    cd "$checkout"
    tar -xf -
)

# Preserve an existing local lockfile; otherwise the first run generates one,
# reused by the second run. Upstream does not commit Cargo.lock.
if [[ -f "$root/Cargo.lock" ]]; then
    cp "$root/Cargo.lock" "$checkout/Cargo.lock"
fi

if [[ -n "$target_dir" ]]; then
    target="$(cd "$(dirname "$target_dir")" && pwd)/$(basename "$target_dir")"
else
    target="$temp/target"
fi

source_file="$checkout/quiche/src/recovery/gcongestion/bbr2/probe_bw.rs"
fixed_copy="$temp/probe_bw.fixed.rs"
cp "$source_file" "$fixed_copy"

fixed_guard='if congestion_event
                .prior_cwnd
                .saturating_sub(congestion_event.prior_bytes_in_flight) >=
                congestion_event.max_datagram_size'
original_guard='if congestion_event.prior_bytes_in_flight <
                congestion_event.prior_cwnd'

FIXED_GUARD="$fixed_guard" ORIGINAL_GUARD="$original_guard" perl -0pi -e '
    BEGIN {
        $fixed = $ENV{FIXED_GUARD};
        $original = $ENV{ORIGINAL_GUARD};
        $count = 0;
    }
    $count += s/\Q$fixed\E/$original/g;
    END {
        die "expected fixed guard exactly once; refusing to change another condition\n"
            unless $count == 1;
    }
' "$source_file"

filter='recovery::gcongestion::bbr2::probe_bw::datagram_cwnd_tests::'
regression='queued_datagrams_grow_probe_up_with_sub_packet_cwnd_remainder'

run_tests() {
    local label=$1
    local output_file=$2

    echo
    echo "=== $label ==="
    set +e
    CARGO_TARGET_DIR="$target" CARGO_TERM_COLOR=never \
        cargo test \
        --manifest-path "$checkout/Cargo.toml" \
        -p quiche \
        "$filter" \
        -- \
        --nocapture \
        --test-threads=1 2>&1 | tee "$output_file"
    test_code=${PIPESTATUS[0]}
    set -e
}

original_output="$temp/original.out"
run_tests "Original guard: expect one regression failure" "$original_output"
if [[ $test_code -ne 101 ]] ||
    ! grep -Fq "ProbeUp wedged with packet size 1400" "$original_output" ||
    ! grep -Fq "2 passed; 1 failed" "$original_output" ||
    ! grep -Fq "$regression" "$original_output"
then
    echo "The expected regression was NOT reproduced (build/toolchain failures do not count)" >&2
    exit 1
fi

cp "$fixed_copy" "$source_file"
fixed_output="$temp/fixed.out"
run_tests "Fixed guard: expect all three tests to pass" "$fixed_output"
if [[ $test_code -ne 0 ]] || ! grep -Fq "3 passed; 0 failed" "$fixed_output"; then
    echo "The fix did not pass all three regression/control tests" >&2
    exit 1
fi

echo
echo "VERIFIED: original guard stalls; fixed guard grows; control cases pass."
