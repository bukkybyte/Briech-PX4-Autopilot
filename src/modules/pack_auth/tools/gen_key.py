#!/usr/bin/env python3
"""Write a random 16-byte SmartPack key header.

  gen_key.py <path> [--force]

Replaces the public dev key without asking. Refuses to overwrite any other key unless
--force is given (changing the key breaks every pack and every signed Cube config).
"""
import os, re, secrets, sys

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    force = "--force" in sys.argv[2:]
    if os.path.exists(path):
        cur = bytes(int(h, 16) for h in re.findall(r'0x([0-9a-fA-F]{2})', open(path).read())[:16])
        if cur != bytes(range(16)) and not force:
            sys.exit("%s already holds a non-dev key. Use --force to replace it "
                     "(all packs and signed configs must then be redone)." % path)
    key = secrets.token_bytes(16)
    rows = ["    " + ", ".join("0x%02x" % b for b in key[i:i + 8]) + "," for i in (0, 8)]
    open(path, "w").write(
        "// SmartPack shared secret. Must be identical on every pack and in the ArduPilot build.\n"
        "// Keep this file out of git.\n"
        "#pragma once\n#include <stdint.h>\n\n"
        "static const uint8_t SMARTPACK_KEY[16] = {\n" + "\n".join(rows) + "\n};\n")
    print("new key written to", path)

if __name__ == "__main__":
    main()
