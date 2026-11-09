# pack_auth: battery-pack authentication for PX4

A battery pack has to prove it is genuine before the flight controller will arm. Each pack also
carries a small record (serial, set, activation date, use count, max count) that you can read and
the aircraft can read and enforce.

This is the PX4 version of the ArduPilot `AP_PackAuth` kit. **The packs, the protocol, the key and the
Nano/Uno sketches are the same**, so a pack provisioned for one flies on the other (the shared
`smartpack_proto.h` is byte-identical). What changed is the autopilot side: a PX4 module, a hook in
Commander, and a PX4 installer.

This folder is **everything**: the module, the pack firmware, the bench-test sketch, the tools and this
guide. It lives in `<px4>/src/modules/pack_auth/` and is committed to your PX4 fork; only the key stays
out of git. (The build compiles only the files listed in `CMakeLists.txt`, so the sketches and tools
below it are never part of the firmware.)

## Status: what has and has not been checked

Checked (by running it): the pack protocol (`setup.sh test`), the real module logic against simulated
packs with a fake clock (scan, challenge, tamper, unplug, swap, sets, signed count, use counting, the
Commander-side fail-closed gate), and the installer on a clean **PX4 v1.17.0** tree and on **PX4 main
(7 Nov 2026)**, including a second run that changes nothing.

Compiled (host `-fsyntax-only`, `-Wall -Wextra`, gate switched on, against a configured v1.17.0 tree
with generated uORB/event/parameter headers): `Commander.cpp`, `HealthAndArmingChecks.cpp`,
`packAuthCheck.cpp` and `pack_auth.cpp`. The NuttX-only `device::I2C` and `I2CBusIterator` were stubbed
for that check, with the same signatures as the real ones.

**Not done: the real ARM build and any hardware test.** Nobody has run `make cubepilot_cubeorange_default`
on this, linked it, or tried it on a Cube. Also not compiled: the PX4 `main` flavour of the module
binding (`PACK_AUTH_MODULEBASE_DESC=1`, picked automatically by CMake); only the installer was run on
main. Do the build and the bench tests (see "Testing") before anything else.

## What it does

- **Genuine-pack check.** The autopilot sends a random challenge; the pack answers with SipHash-2-4 over
  (challenge + its record) using a shared 16-byte key. No key, no valid answer.
- **Not bypassable by settings.** The check sits inside `Commander::arm()`, which is the only place PX4
  sets the armed state. Force-arm, arm-on-boot and the 5 s RC re-arm grace period all go through it, and
  the gate is evaluated *before* they can skip preflight checks. If the module is not running, or stops
  publishing, the gate is closed (fail closed). There is no parameter that turns it off.
- **Fresh proof.** Each pack is re-challenged every 3 s while disarmed, so an unplugged, tampered or
  swapped pack is noticed within seconds. Nothing touches the bus while armed.
- **Pack record.** serial (unique per pack), set id (shared by one set), activation date, use count,
  max count. A pack is refused once `count >= max_count`.
- **Use counting.** One use is added when the vehicle disarms after being armed at least
  `PACK_AUTH_MIN_FLIGHT_S` (default 30 s; 0 = every arm). The report is an authenticated, one-shot
  message, so it cannot be forged or replayed.
- **Sets.** Every required pack must carry the same set id.
- **1 to 5 packs per aircraft.** `PKA_NUM` says how many; a signature (made with the key, bound to this
  autopilot's unique id) stops anyone changing that number without the key.

## How it works

```
 PACK (Nano / MCU)                    I2C                 FLIGHT CONTROLLER (Cube, PX4)
 +---------------------+       +-------------+      +----------------------------------------+
 | EEPROM record       | <---> | SDA, SCL    | <--> | pack_auth module (own task)            |
 |  serial, set, date  |       | 100 kHz     |      |  per pack: read INFO, send nonce,      |
 |  count, max         |       +-------------+      |  poll, verify, report use after flight |
 | answers challenges  |                            |      |  publishes pack_auth_status (10 Hz)  |
 | counts reported uses|                            | Commander::arm()    -> gate            |
 +---------------------+                            | HealthAndArmingChecks -> pre-arm text  |
                                                    +----------------------------------------+
```

`pack_auth_core.cpp` has no PX4 includes: the very same file is compiled into the firmware and into the
host simulator. `pack_auth.cpp` binds it to PX4 (I2C, parameters, uORB). `pack_auth_gate.h` is the
fail-closed decision Commander makes on the published status (missing or older than 2 s = closed).

### I2C protocol v2 (`smartpack_proto.h`, identical on every device and on the ArduPilot side)

| Reg | Dir | Content |
|---|---|---|
| 0x70 NONCE | write 8 | random challenge |
| 0x71 STATUS | read 1 | 0 idle, 1 busy, 2 ready (the pack never clock-stretches) |
| 0x72 RESPONSE | read 8 | `SipHash24(key, nonce + info[16])` |
| 0x73 INFO | read 16 | the pack record (below) |
| 0x74 USE | write 8 | `SipHash24(key, 0x55 + nonce + info[16])`, valid once, for the last challenge only |

INFO (little endian): `serial u16 | set_id u32 | activated u32 (YYYYMMDD) | count u16 | max_count u16 | flags u8 | reserved u8`.
All zeros while the pack is not provisioned.

### When arming is refused

Two messages can appear, from two places. The pre-arm check shows `Preflight Fail: ...` while you wait;
`Commander::arm()` shows `Arming denied: ...` when an arm is actually attempted (including a forced one).

| Text | Meaning |
|---|---|
| `Pack auth: not running` | the `pack_auth` module is not started (check `rc.board_sensors`) |
| `Pack auth: task stalled` | the module stopped publishing for more than 2 s |
| `Pack auth: starting` | first seconds after boot |
| `Pack auth: bad pack address config` | `PKA_ADDR + PKA_NUM - 1` is past 0x77 (or `PKA_ADDR` < 8) |
| `Pack auth: pack count not signed` | `PKA_NUM` has no valid signature for this autopilot |
| `Pack N: pack not found` | nothing answers at that slot's address |
| `Pack N: no answer on I2C` / `nonce write failed` / `pack not responding` | bus error / pack too slow |
| `Pack N: wrong response` | wrong key, tampered or counterfeit pack |
| `Pack N: pack not provisioned` | genuine pack with no serial, set or max count yet |
| `Pack N: life used up` | `count >= max_count` |
| `Pack N: other set` | pack N's set id differs from pack 1's |
| `Pack N: proof is stale` | last good answer is older than 8 s |

Other GCS lines: `PackAuth: N pack(s) required`, `Pack 1: #4660 set 100 use 12/500` (pack accepted),
`Pack 1: use 13/500` (flight counted), `Pack 1: use not saved` (5 tries failed).
`pack_auth status` in the NSH console prints the gate, every slot, bus found, record and counters.
The topic `pack_auth_status` is logged at 1 Hz.

## Folder contents

```
src/modules/pack_auth/
  pack_auth.cpp/.hpp                         PX4 binding: task, I2C, parameters, uORB
  pack_auth_core.cpp/.hpp, pack_auth_config.h   the authenticator logic (no PX4 includes)
  pack_auth_gate.h, pack_auth_reasons.h      the fail-closed consumer side, reason codes
  CMakeLists.txt  Kconfig  module.yaml       build entry, board options, parameters
  smartpack_proto.h                          the protocol header: single source of truth
  smartpack_key.h.example                    public dev key, as a template
  smartpack_key.h                            YOUR key - created by setup.sh, never committed (.gitignore)
  setup.sh                                   key / sync / test / install / sign   (bash setup.sh ...)
  integration/                               PackAuthStatus.msg, packAuthCheck.cpp/.hpp: copied into PX4 by install
  nano/smartpack_nano/                       pack firmware (Arduino Nano) + pack-side logic
  uno/uno_multi_master/                      bench test master (Uno) for 1-5 packs
  tools/                                     apply_patch.py  sign_config.py  gen_key.py  protocol_test.cpp
  tools/sim/                                 runs the REAL core against simulated packs, fake clock
```

## Setting up

Use a **release tag** (v1.17.0 is the validated one) rather than a moving branch. Anchors were also
checked on main of 7 Nov 2026.

### A. Your fork already has this on a branch (normal case)

```bash
git clone --recurse-submodules -b packauth https://github.com/<you>/PX4-Autopilot ~/px4
cd ~/px4/src/modules/pack_auth
cp /safe/place/smartpack_key.h .      # your key (the same one every pack uses); or: bash setup.sh key
bash setup.sh sync                    # key + protocol header into the Nano and Uno sketch folders
bash setup.sh test                    # host tests: must end with ALL SIM TESTS PASSED twice
cd ~/px4 && make cubepilot_cubeorange_default
```
Flash `build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.px4` (QGroundControl: Vehicle Setup >
Firmware > Advanced settings > Custom firmware file).

### B. Add it to a clean PX4 tree

```bash
cd ~/px4                               # a v1.17.0 checkout with submodules
unzip PX4_PackAuth.zip -d src/modules/ && mv src/modules/PX4_PackAuth src/modules/pack_auth
cd src/modules/pack_auth
bash setup.sh key                      # random key (replaces the public dev key)
bash setup.sh install --dry-run        # shows what will be edited
bash setup.sh install                  # edits 6 source files, adds 3, and adds the board config + start line; safe to repeat
cd ~/px4 && make cubepilot_cubeorange_default
```
`install` options: `--board <vendor/model>` (repeatable, default `cubepilot/cubeorange`), `--unsigned`
(plain `PKA_NUM`, no signature; bench work), `--min-flight <s>`, `--dry-run`. It also recognises the same
edits made by hand. If an anchor is not found it makes no edit and prints the snippet to add yourself
(exit code 2). `bash setup.sh install /path/to/other/tree` copies this whole folder into another tree first.

What `install` touches:

| File | Edit |
|---|---|
| `msg/CMakeLists.txt`, `msg/PackAuthStatus.msg` | the status message |
| `src/modules/commander/Commander.cpp/.hpp` | the gate in `Commander::arm()`, the subscription |
| `src/modules/commander/HealthAndArmingChecks/` (`CMakeLists.txt`, `HealthAndArmingChecks.hpp`, `checks/packAuthCheck.*`) | the pre-arm check and its messages |
| `src/modules/logger/logged_topics.cpp` | log `pack_auth_status` |
| `boards/<board>/default.px4board`, `init/rc.board_sensors` | `CONFIG_MODULES_PACK_AUTH=y`, `pack_auth start` |

The module is NuttX-only (`depends on PLATFORM_NUTTX`) and is enabled **per board**; SITL builds are
unchanged. Other STM32 boards: pass `--board`, and check that the board has an `init/rc.board_sensors`
(`install` creates one if not).

### C. Commit and push to your fork

```bash
cd ~/px4 && git checkout -b packauth
git add src/modules/pack_auth src/modules/commander src/modules/logger msg boards/cubepilot/cubeorange
git status --short      # only smartpack_key.h.example may appear - no smartpack_key.h anywhere
git commit -m "pack_auth: battery pack authentication" && git push -u origin packauth
```
Keep a copy of `smartpack_key.h` somewhere safe (password manager, encrypted drive): it is the only thing
the fork does not have.

## Packs, wiring, Cube

**Pack (Nano).** Open `nano/smartpack_nano` in the Arduino IDE (Nano, ATmega328P), upload, open the serial
monitor at 115200 and provision each pack once:

```
n 4660          serial (unique for every pack)
g 100           set id (the same for every pack of one set)
d 20261031      activation date YYYYMMDD
m 500           max count
a 12            I2C address (decimal, 8..119), applied after a reset; default 0x0B
p               print the record
```
Other commands: `c <count>` set the count (service/testing), `v <mV>`, `i <mA>`, `t` tamper (wrong response).

**Wiring** (Nano is 5 V, the Cube 3.3 V): SDA/SCL through a BSS138-type I2C level shifter (LV = 3.3 V,
HV = 5 V, common GND), pull-ups on both sides, 4.7-10 kOhm. Identify SDA/SCL on the carrier with a meter
(GND and +5 V are the other two pins). Never feed a 5 V line into the Cube side.

**Cube.** PX4 numbers I2C buses from 1; on the Cube Orange both I2C buses are external. With the packs
connected, read the boot messages (MAVLink console / QGC): `PackAuth: count not signed, detecting`, then
`PackAuth: N pack(s) detected` and `PackAuth cfg-id: <24 hex>`. Sign the count for that autopilot:

```bash
bash setup.sh sign <cfg-id> <N> > cube1.params
```
Load `cube1.params` in QGroundControl (Vehicle Setup > Parameters > Tools > Load from file) and reboot.
(`--format nsh` prints `param set` lines instead, for the console.) You should see
`PackAuth: N pack(s) required`, and the pack gate passes.

**Addresses.** Pack N is at `PKA_ADDR + N - 1` (default 11 = 0x0B). Keep the range clear of other
devices on the bus. `PKA_BUS` -1 scans every *external* I2C bus for each pack; set it to the bus number
once you know it (`pack_auth status` shows `bus=`). To replace a pack, give the spare the dead pack's
address (`a <addr>`), same set, unique serial. The Cube needs nothing: it sees the new serial and proves
the slot again within seconds.

## Configuration

Parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `PKA_BUS` | -1 | I2C bus of the packs (from 1); -1 = scan all external buses per pack (reboot) |
| `PKA_ADDR` | 11 | address of pack 1; pack N = ADDR + N - 1 (reboot) |
| `PKA_NUM` | 1 | packs that must authenticate, 1..5 (reboot) |
| `PKA_S0..S3` | 0 | signature of NUM for this autopilot (from `sign`; unsigned 0..65535) |

Build switches (in the board's `default.px4board`, or `make <board> boardconfig`):

| Switch | Default | Meaning |
|---|---|---|
| `CONFIG_MODULES_PACK_AUTH` | n | build the module and the Commander hook (the installer sets y) |
| `CONFIG_PACK_AUTH_UNSIGNED_COUNT` | n | y = no signature needed on `PKA_NUM` (bench only) |
| `CONFIG_PACK_AUTH_NUM_MIN` | 1 | floor: the count can never be set below this |
| `CONFIG_PACK_AUTH_MIN_FLIGHT_S` | 30 | armed time that counts as a use; 0 = every arm |

Timing (`pack_auth_config.h`): rescan 2 s, retry 1 s, pack reply timeout 0.4 s, re-challenge 3 s,
proof valid 8 s, status valid 2 s, 5 attempts to report a use.

## Testing

| Test | How | Expect |
|---|---|---|
| Host | `bash setup.sh test` | `ALL TESTS PASSED`, then `ALL SIM TESTS PASSED` twice; the 40 s flight is counted, the 5 s one is not (30 s rule) |
| Build | `make cubepilot_cubeorange_default` | builds; `pack_auth` is in the image |
| Nano self-test | boot the Nano with the dev key | `self-test response: 672EDC8C1FB809AF` (differs with your own key) |
| Pack alone | Uno with `uno_multi_master` (set `BASE_ADDR`, `NUM_PACKS`) | `OK` per pack; `t` on a Nano gives `MISMATCH` there only |
| Use report | Uno with `TEST_USE 1`, once | `use report: count N -> N+1` |
| Gate | Cube, any arm attempt without a good pack | `Arming denied: Pack ...` even with a forced arm (`commander arm -f`) |
| Fail closed | `pack_auth stop`, wait 2 s, then arm | `Arming denied: Pack auth: task stalled` (never started: `not running`) |
| Counting | arm >= 30 s, disarm | `Pack 1: use N/500` (bench: build with `CONFIG_PACK_AUTH_MIN_FLIGHT_S=0`) |
| Signed count | change `PKA_NUM` by hand | `pack count not signed` |

## Before real flights

1. `bash setup.sh key` and rebuild: the shipped dev key is public. Changing it later means redoing every
   pack and every signed autopilot.
2. Set the ATmega lock bits on the packs so the key cannot be read out over ISP.
3. Do not use `CONFIG_PACK_AUTH_UNSIGNED_COUNT` on a flying build.
4. Re-run the gate, tamper, unplug and `pack_auth stop` tests on the final build.

## Resource use

Not measured. The module is one task with a 3 KB stack (`PX4_STACK_ADJUSTED(3000)`), a hash takes
microseconds, and I2C is about 4-5 ms per pack every 3 s with nothing in flight. Measure on your build:
compare the image size with `CONFIG_MODULES_PACK_AUTH` n and y, and watch `top` / the logged CPU load.

## Differences from the ArduPilot kit

| | ArduPilot (`AP_PackAuth`) | PX4 (`pack_auth`) |
|---|---|---|
| Gate | `AP_Arming::arm()` | `Commander::arm()` + a `HealthAndArmingChecks` check |
| Parameters | `ARMING_PKA_*`, signature words signed int16 | `PKA_*`, signature words unsigned 0..65535 |
| Param file / tool | Mission Planner `name,value` | QGC `.params` (or `param set` lines) |
| Bus numbering, scan | from 0, all buses | from 1, external buses only |
| Switches | `hwdef.dat` defines | `.px4board` Kconfig |
| Debug text | `AP_PACKAUTH_DEBUG` | `pack_auth status` command, logged `pack_auth_status` |
| Unique id used for the signature | 12-byte chip id | 12-byte chip id (`board_get_uuid`) |
| Packs, key, protocol, sketches | same | same |

Always sign from the cfg-id the PX4 build itself prints; do not reuse a signature made for an ArduPilot build of the same Cube.

## Limits

- The use counter is only as strong as the pack: whoever can rewrite the pack's EEPROM can reset it (the `c` command does).
- A flight that ends in a power cut before disarm is not counted.
- Anyone who can flash firmware can remove the gate; for that you need signed firmware / secure boot.
- Packs must sit at consecutive addresses, and a spare must be given the failed pack's address.
- The signature is only as secret as the key, and the key is in the firmware image.
- The gate is checked when arming. A pack that fails *after* arming does not disarm the aircraft.
- NuttX boards only (the module is not built for SITL).

## Roadmap

CAN transport (the nonce, MAC, record and gate stay; only the I2C reads and writes change), an I2C
multiplexer or coding pins for address-free pack swaps, binding the set id into the signed config.
