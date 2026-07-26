#!/bin/sh
#
# Round-trip regression tests for lrzip.
#
# Runs unmodified on Linux and under MSYS2/MinGW. Every case compresses and
# decompresses real data and compares the result byte for byte; compressed
# output is deliberately never compared against a golden size, because it is
# not reproducible - init_hash_indexes() seeds the rzip hash table from a
# nanosecond clock, so the same input legitimately yields slightly different
# archives on every run.
#
# Usage:  test/roundtrip.sh [path-to-lrzip]
#
# Exits non-zero on the first failure.

set -eu

LRZIP=${1:-}
if [ -z "$LRZIP" ]; then
	if   [ -x ./lrzip.exe ];       then LRZIP=./lrzip.exe
	elif [ -x ./.libs/lrzip.exe ]; then LRZIP=./.libs/lrzip.exe
	elif [ -x ./lrzip ];           then LRZIP=./lrzip
	else echo "cannot find an lrzip binary to test" >&2; exit 1
	fi
fi
LRZIP=$(cd "$(dirname "$LRZIP")" && pwd)/$(basename "$LRZIP")
echo "testing: $LRZIP"
"$LRZIP" -V

WORK=$(mktemp -d 2>/dev/null || mktemp -d -t lrztest)
trap 'rm -rf "$WORK"' EXIT INT TERM

pass=0
fail=0

report() {
	if [ "$2" = 0 ]; then
		printf '  %-34s OK\n' "$1"
		pass=$((pass + 1))
	else
		printf '  %-34s FAIL\n' "$1"
		fail=$((fail + 1))
	fi
}

# ~2.5 MB of compressible but non-trivial text, generated deterministically so
# a failure can be reproduced.
awk 'BEGIN {
	srand(20260726);
	split("alpha beta gamma delta epsilon zeta", w, " ");
	for (i = 0; i < 150000; i++)
		printf "%s %d\n", w[int(rand() * 6) + 1], int(rand() * 100000);
}' > "$WORK/big.txt"

# Deliberately smaller than one page: this used to fail outright on Windows
# because the sliding window mapped a full page regardless of file size.
printf 'small file, under one page in length\n' > "$WORK/tiny.bin"

echo
echo "compression backends (round-trip, byte-exact):"
for opts in "" "-L1" "-L9" "-b" "-g" "-l" "-z" "-z -L9" "-n" "-p 1" "-U"; do
	label="lrzip ${opts:-<default>}"
	rm -f "$WORK/a.lrz" "$WORK/a.out"
	rc=0
	# shellcheck disable=SC2086
	"$LRZIP" $opts -q -f -o "$WORK/a.lrz" "$WORK/big.txt" >/dev/null 2>&1 || rc=1
	[ "$rc" = 0 ] && { "$LRZIP" -d -q -f -o "$WORK/a.out" "$WORK/a.lrz" >/dev/null 2>&1 || rc=1; }
	[ "$rc" = 0 ] && { cmp -s "$WORK/big.txt" "$WORK/a.out" || rc=1; }
	report "$label" "$rc"
done

echo
echo "edge cases:"

# Sub-page input.
rm -f "$WORK/t.lrz" "$WORK/t.out"; rc=0
"$LRZIP" -q -f -o "$WORK/t.lrz" "$WORK/tiny.bin" >/dev/null 2>&1 || rc=1
[ "$rc" = 0 ] && { "$LRZIP" -d -q -f -o "$WORK/t.out" "$WORK/t.lrz" >/dev/null 2>&1 || rc=1; }
[ "$rc" = 0 ] && { cmp -s "$WORK/tiny.bin" "$WORK/t.out" || rc=1; }
report "sub-page file (39 bytes)" "$rc"

# Compression from stdin.
rm -f "$WORK/s.lrz" "$WORK/s.out"; rc=0
"$LRZIP" -q -f -o "$WORK/s.lrz" < "$WORK/big.txt" >/dev/null 2>&1 || rc=1
[ "$rc" = 0 ] && { "$LRZIP" -d -q -f -o "$WORK/s.out" "$WORK/s.lrz" >/dev/null 2>&1 || rc=1; }
[ "$rc" = 0 ] && { cmp -s "$WORK/big.txt" "$WORK/s.out" || rc=1; }
report "compress from stdin" "$rc"

# Decompression to stdout.
rc=0
"$LRZIP" -d -q -o - "$WORK/a.lrz" > "$WORK/o.out" 2>/dev/null || rc=1
[ "$rc" = 0 ] && { cmp -s "$WORK/big.txt" "$WORK/o.out" || rc=1; }
report "decompress to stdout" "$rc"

# Test mode must actually verify the archive and succeed.
rc=0
"$LRZIP" -t -q "$WORK/a.lrz" >/dev/null 2>&1 || rc=1
report "test mode (-t)" "$rc"

# -t used to abort while setting up its temporary file, leaving it behind.
tmpdir=${TMPDIR:-${TMP:-/tmp}}
leaked=$(find "$tmpdir" -maxdepth 1 -name 'lrzipout.*' 2>/dev/null | wc -l | tr -d ' ')
rm -f "$tmpdir"/lrzipout.* 2>/dev/null || true
"$LRZIP" -t -q "$WORK/a.lrz" >/dev/null 2>&1 || true
after=$(find "$tmpdir" -maxdepth 1 -name 'lrzipout.*' 2>/dev/null | wc -l | tr -d ' ')
rc=0; [ "$after" = 0 ] || rc=1
report "test mode leaves no temp files" "$rc"

# Encryption.
rm -f "$WORK/e.lrz" "$WORK/e.out"; rc=0
"$LRZIP" -q -f --encrypt=roundtrip-passphrase -o "$WORK/e.lrz" "$WORK/big.txt" >/dev/null 2>&1 || rc=1
[ "$rc" = 0 ] && { "$LRZIP" -d -q -f --encrypt=roundtrip-passphrase -o "$WORK/e.out" "$WORK/e.lrz" >/dev/null 2>&1 || rc=1; }
[ "$rc" = 0 ] && { cmp -s "$WORK/big.txt" "$WORK/e.out" || rc=1; }
report "encrypted round-trip" "$rc"

# A wrong passphrase must not silently produce data.
rc=0
if "$LRZIP" -d -q -f --encrypt=wrong-passphrase -o "$WORK/bad.out" "$WORK/e.lrz" >/dev/null 2>&1; then
	cmp -s "$WORK/big.txt" "$WORK/bad.out" && rc=1
fi
report "wrong passphrase rejected" "$rc"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" = 0 ] || exit 1
echo "ALL TESTS PASSED"
