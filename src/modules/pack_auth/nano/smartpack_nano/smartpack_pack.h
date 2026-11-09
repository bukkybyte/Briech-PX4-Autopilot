// smartpack_pack.h - pack-side record handling. No Arduino dependencies, so the exact same
// code runs on the Nano and in the host test (protocol_test.cpp).
#pragma once

#include "smartpack_proto.h"

struct SmartPackRecord {              // what is kept in EEPROM
    uint16_t serial;                  // unique per physical pack
    uint32_t set_id;                  // shared by all packs of one set
    uint32_t activated;               // YYYYMMDD, 0 = not set
    uint16_t count;                   // uses so far
    uint16_t max_count;               // not usable once count >= max_count
};

struct SmartPackState {
    SmartPackRecord rec;
    uint8_t nonce[SMARTPACK_NONCE_LEN];   // last challenge served
    bool nonce_valid;                     // true until it is used up by a USE or replaced
};

static inline bool smartpack_provisioned(const SmartPackRecord &r)
{
    return r.serial != 0 && r.set_id != 0 && r.max_count != 0;
}

static inline bool smartpack_rec_equal(const SmartPackRecord &a, const SmartPackRecord &b)
{
    return a.serial == b.serial && a.set_id == b.set_id && a.activated == b.activated &&
           a.count == b.count && a.max_count == b.max_count;
}

// the 16 byte INFO register; all zeros while the pack is not provisioned
static inline void smartpack_build_info(const SmartPackRecord &r, uint8_t out[SMARTPACK_INFO_LEN])
{
    memset(out, 0, SMARTPACK_INFO_LEN);
    if (!smartpack_provisioned(r)) {
        return;
    }
    out[0] = (uint8_t)(r.serial);          out[1] = (uint8_t)(r.serial >> 8);
    for (uint8_t i = 0; i < 4; i++) {
        out[2 + i] = (uint8_t)(r.set_id >> (8 * i));
        out[6 + i] = (uint8_t)(r.activated >> (8 * i));
    }
    out[10] = (uint8_t)(r.count);          out[11] = (uint8_t)(r.count >> 8);
    out[12] = (uint8_t)(r.max_count);      out[13] = (uint8_t)(r.max_count >> 8);
    out[14] = (r.count >= r.max_count) ? SMARTPACK_FLAG_EXHAUSTED : 0;
}

// A USE is handled in three steps so the slow hash never runs with interrupts off:
//   1. (interrupts on)  snap = live
//   2. (interrupts on)  ok = smartpack_use_check(key, snap, mac)
//   3. (interrupts off) if (ok) counted = smartpack_use_commit(live, snap)

// step 2: is this MAC valid for the challenge and record in the snapshot?
static inline bool smartpack_use_check(const uint8_t key[16], const SmartPackState &snap,
                                       const uint8_t mac[SMARTPACK_USE_LEN])
{
    if (!snap.nonce_valid || !smartpack_provisioned(snap.rec)) {
        return false;
    }
    uint8_t info[SMARTPACK_INFO_LEN], want[SMARTPACK_USE_LEN];
    smartpack_build_info(snap.rec, info);
    smartpack_compute_use_mac(key, snap.nonce, info, want);
    uint8_t diff = 0;
    for (uint8_t i = 0; i < SMARTPACK_USE_LEN; i++) {
        diff |= want[i] ^ mac[i];
    }
    return diff == 0;
}

// step 3: only if nothing changed since the snapshot. Consumes the challenge (so a replay
// fails) and counts one use. The caller then saves the record.
static inline bool smartpack_use_commit(SmartPackState &live, const SmartPackState &snap)
{
    if (!live.nonce_valid ||
        memcmp(live.nonce, snap.nonce, SMARTPACK_NONCE_LEN) != 0 ||
        !smartpack_rec_equal(live.rec, snap.rec)) {
        return false;
    }
    live.nonce_valid = false;
    if (live.rec.count != 0xFFFF) {
        live.rec.count++;
    }
    return true;
}
