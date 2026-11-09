#!/usr/bin/env bash
# pack_auth helper. This folder lives in <px4>/src/modules/pack_auth.  Run: bash setup.sh help
set -euo pipefail
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY="$LIB/smartpack_key.h"
SKETCHES=("$LIB/nano/smartpack_nano" "$LIB/uno/uno_multi_master")
HOME_ROOT="$(cd "$LIB/../../.." 2>/dev/null && pwd || true)"      # the PX4 tree this folder sits in

die() { echo "error: $*" >&2; exit 1; }

usage() { cat <<'U'
usage: bash setup.sh <command>

  key [--force]            make a random key (replaces the public dev key) and copy it to the sketches
  sync                     copy smartpack_proto.h and the key into the Nano and Uno sketch folders
  test                     host tests: protocol checks + the arm/disarm simulation (no hardware)
  install [px4-dir] [--board vendor/model] [--unsigned] [--min-flight S] [--dry-run]
                           hook the module into PX4 (default: the tree this folder is in).
                           With another tree it first copies this whole folder there. Safe to repeat.
  sign <cfg-id> <packs> [--format qgc|nsh|raw]
                           parameters that sign the pack count for one autopilot (cfg-id from the GCS)
U
}

cmd_sync() {
    [ -f "$KEY" ] || die "no $KEY - run: bash setup.sh key   (or copy your existing key here)"
    for d in "${SKETCHES[@]}"; do cp "$LIB/smartpack_proto.h" "$KEY" "$d/"; done
    echo "synced smartpack_proto.h + key into: ${SKETCHES[*]##*/}"
}

cmd_key() {
    python3 "$LIB/tools/gen_key.py" "$KEY" "$@"
    cmd_sync
    echo "Rebuild the firmware and upload the Nano sketch again. Every pack and every signed"
    echo "autopilot config must use the new key."
}

cmd_test() {
    local W; W="$(mktemp -d)"; trap 'rm -rf "$W"' RETURN
    if [ -f "$KEY" ]; then cp "$KEY" "$W/smartpack_key.h"
    else cp "$LIB/smartpack_key.h.example" "$W/smartpack_key.h"; echo "(no key yet: testing with the public dev key)"; fi
    cp "$LIB/smartpack_proto.h" "$LIB/nano/smartpack_nano/smartpack_pack.h" "$LIB/tools/protocol_test.cpp" "$W"
    g++ -std=c++11 -Wall -Wextra -I"$W" "$W/protocol_test.cpp" -o "$W/protocol_test"
    "$W/protocol_test"
    echo
    bash "$LIB/tools/sim/run.sh"
}

cmd_install() {
    local root="$HOME_ROOT"
    if [ $# -ge 1 ] && [[ "$1" != --* ]]; then root="$(cd "$1" && pwd)"; shift; fi
    [ -f "$root/src/modules/commander/Commander.cpp" ] || \
        die "$root is not a PX4 tree. Run this from <px4>/src/modules/pack_auth, or pass the tree."
    if [ "$root/src/modules/pack_auth" != "$LIB" ]; then
        mkdir -p "$root/src/modules/pack_auth"
        cp -r "$LIB/." "$root/src/modules/pack_auth/"
        echo "copied this folder to $root/src/modules/pack_auth"
    fi
    [ -f "$root/src/modules/pack_auth/smartpack_key.h" ] || die "no key - run: bash setup.sh key"
    python3 "$root/src/modules/pack_auth/tools/apply_patch.py" "$root" "$@"
    cat <<N

next:
  cd $root
  git submodule update --init --recursive      # once, on a fresh clone
  make cubepilot_cubeorange_default            # (or your board)
  flash build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.px4 (QGroundControl: Vehicle Setup > Firmware > custom file)
N
}

cmd_sign() {
    [ $# -ge 2 ] || die "usage: bash setup.sh sign <24-hex cfg-id> <packs 1..5> [--format qgc|nsh|raw]"
    [ -f "$KEY" ] || die "no key - run: bash setup.sh key"
    local uid="$1" n="$2"; shift 2
    python3 "$LIB/tools/sign_config.py" --key "$KEY" --uid "$uid" --packs "$n" "$@"
}

c="${1:-help}"; shift || true
case "$c" in
    key) cmd_key "$@" ;;
    sync) cmd_sync ;;
    test) cmd_test ;;
    install) cmd_install "$@" ;;
    sign) cmd_sign "$@" ;;
    *) usage ;;
esac
