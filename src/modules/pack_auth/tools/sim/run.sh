#!/usr/bin/env bash
# Run the REAL pack_auth_core.cpp and pack_auth_gate.h (the files the firmware compiles) against
# simulated packs that run the REAL pack-side code of the Nano sketch, with a fake clock. No hardware.
# Replays two flights (5 s and 40 s) with the default and with a 0 s minimum flight time.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/../.."
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp "$LIB"/pack_auth_core.cpp "$LIB"/pack_auth_core.hpp "$LIB"/pack_auth_config.h "$LIB"/pack_auth_gate.h \
   "$LIB"/pack_auth_reasons.h "$LIB"/smartpack_proto.h "$W"
if [ -f "$LIB/smartpack_key.h" ]; then KEYF="$LIB/smartpack_key.h"; else KEYF="$LIB/smartpack_key.h.example"; fi
cp "$KEYF" "$W/smartpack_key.h"
cp "$LIB/nano/smartpack_nano/smartpack_pack.h" "$HERE/sim_test.cpp" "$W"
# the sim's fake autopilot has unique id 00 01 02 .. 0b; sign the pack count for it with the real tool
UID_HEX=000102030405060708090a0b
S1=$(python3 "$LIB/tools/sign_config.py" --key "$KEYF" --uid $UID_HEX --packs 1 --format raw)
S2=$(python3 "$LIB/tools/sign_config.py" --key "$KEYF" --uid $UID_HEX --packs 2 --format raw)
for s in 30 0; do
    echo "=== PACK_AUTH_MIN_FLIGHT_S=$s"
    g++ -std=gnu++11 -Wall -Wextra -I"$W" -DPACK_AUTH_MIN_FLIGHT_S=$s "$W/sim_test.cpp" -o "$W/sim$s"
    "$W/sim$s" $S1 $S2
done
