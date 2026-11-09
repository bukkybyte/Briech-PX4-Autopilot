// SmartPack I2C protocol v2 - shared by the pack firmware (Arduino/MCU), the ArduPilot
// AP_PackAuth module and any test master. Keep this file byte-identical everywhere.
//
//   0x70  NONCE     write   : [0x70, n0..n7]       FC sends an 8-byte random challenge
//   0x71  STATUS    read 1  : 0=idle 1=busy 2=ready
//   0x72  RESPONSE  read 8  : SipHash-2-4(key, nonce || info[16]), little endian
//   0x73  INFO      read 16 : the pack record (layout below)
//   0x74  USE       write   : [0x74, mac0..mac7]   FC reports one use of the pack
//                             mac = SipHash-2-4(key, 0x55 || nonce || info[16])
//                             Valid once, and only for the last challenge the pack served.
//
// INFO layout, little endian:
//   [0..1]   serial      u16  unique per physical pack
//   [2..5]   set_id      u32  every pack of one set carries the same value
//   [6..9]   activated   u32  YYYYMMDD, 0 = not set
//   [10..11] count       u16  uses so far
//   [12..13] max_count   u16  the pack may not be used once count >= max_count
//   [14]     flags       u8   bit0 = exhausted (count >= max_count)
//   [15]     reserved    u8
// A pack that is not provisioned (serial, set_id or max_count zero) reports all zeros.
//
// Telemetry uses standard Smart Battery (SBS) registers. The pack must NOT stretch the
// clock while computing: it sets STATUS=busy on receiving the nonce and the FC polls
// until STATUS=ready.
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SMARTPACK_REG_NONCE      0x70
#define SMARTPACK_REG_STATUS     0x71
#define SMARTPACK_REG_RESPONSE   0x72
#define SMARTPACK_REG_INFO       0x73
#define SMARTPACK_REG_USE        0x74

#define SMARTPACK_NONCE_LEN      8
#define SMARTPACK_RESPONSE_LEN   8
#define SMARTPACK_INFO_LEN       16
#define SMARTPACK_USE_LEN        8
#define SMARTPACK_USE_TAG        0x55

#define SMARTPACK_ST_IDLE        0
#define SMARTPACK_ST_BUSY        1
#define SMARTPACK_ST_READY       2

#define SMARTPACK_FLAG_EXHAUSTED 0x01

// ---- SipHash-2-4 (public domain algorithm, Aumasson & Bernstein) ----
// A keyed MAC designed for short messages: no library needed on either end.

#define SMARTPACK_ROTL64(x, b) ((uint64_t)(((x) << (b)) | ((x) >> (64 - (b)))))

static inline uint64_t smartpack_load64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (uint8_t i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

#define SMARTPACK_SIPROUND                                         \
    do {                                                           \
        v0 += v1; v1 = SMARTPACK_ROTL64(v1, 13); v1 ^= v0;         \
        v0 = SMARTPACK_ROTL64(v0, 32);                             \
        v2 += v3; v3 = SMARTPACK_ROTL64(v3, 16); v3 ^= v2;         \
        v0 += v3; v3 = SMARTPACK_ROTL64(v3, 21); v3 ^= v0;         \
        v2 += v1; v1 = SMARTPACK_ROTL64(v1, 17); v1 ^= v2;         \
        v2 = SMARTPACK_ROTL64(v2, 32);                             \
    } while (0)

static inline uint64_t smartpack_siphash24(const uint8_t key[16], const uint8_t *in, size_t inlen)
{
    const uint64_t k0 = smartpack_load64le(key);
    const uint64_t k1 = smartpack_load64le(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *end = in + (inlen - (inlen % 8));
    for (; in != end; in += 8) {
        const uint64_t m = smartpack_load64le(in);
        v3 ^= m;
        SMARTPACK_SIPROUND;
        SMARTPACK_SIPROUND;
        v0 ^= m;
    }

    uint64_t b = ((uint64_t)inlen) << 56;
    for (uint8_t i = 0; i < (inlen & 7); i++) {
        b |= (uint64_t)in[i] << (8 * i);
    }
    v3 ^= b;
    SMARTPACK_SIPROUND;
    SMARTPACK_SIPROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SMARTPACK_SIPROUND;
    SMARTPACK_SIPROUND;
    SMARTPACK_SIPROUND;
    SMARTPACK_SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static inline uint16_t smartpack_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t smartpack_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void smartpack_put64le(uint8_t out[8], uint64_t t)
{
    for (uint8_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(t >> (8 * i));
    }
}

// response = SipHash-2-4(key, nonce[8] || info[16]). The whole record is under the MAC,
// so none of its fields (serial, set, count, max) can be changed by anything on the bus.
static inline void smartpack_compute_response(const uint8_t key[16],
                                              const uint8_t nonce[SMARTPACK_NONCE_LEN],
                                              const uint8_t info[SMARTPACK_INFO_LEN],
                                              uint8_t out[SMARTPACK_RESPONSE_LEN])
{
    uint8_t msg[SMARTPACK_NONCE_LEN + SMARTPACK_INFO_LEN];
    memcpy(msg, nonce, SMARTPACK_NONCE_LEN);
    memcpy(msg + SMARTPACK_NONCE_LEN, info, SMARTPACK_INFO_LEN);
    smartpack_put64le(out, smartpack_siphash24(key, msg, sizeof(msg)));
}

// use report = SipHash-2-4(key, 0x55 || nonce[8] || info[16]); the tag keeps it apart from
// a challenge response.
static inline void smartpack_compute_use_mac(const uint8_t key[16],
                                             const uint8_t nonce[SMARTPACK_NONCE_LEN],
                                             const uint8_t info[SMARTPACK_INFO_LEN],
                                             uint8_t out[SMARTPACK_USE_LEN])
{
    uint8_t msg[1 + SMARTPACK_NONCE_LEN + SMARTPACK_INFO_LEN];
    msg[0] = SMARTPACK_USE_TAG;
    memcpy(msg + 1, nonce, SMARTPACK_NONCE_LEN);
    memcpy(msg + 1 + SMARTPACK_NONCE_LEN, info, SMARTPACK_INFO_LEN);
    smartpack_put64le(out, smartpack_siphash24(key, msg, sizeof(msg)));
}
