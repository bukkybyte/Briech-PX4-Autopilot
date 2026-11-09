// Host test for the v2 pack protocol: runs the SAME pack-side code as the Nano sketch
// (smartpack_pack.h) against a Cube-side model of what the pack_auth module does.
//
//   g++ -std=c++11 -I../../smartpack_nano -I../../AP_PackAuth protocol_test.cpp -o protocol_test && ./protocol_test
//
// (smartpack_key.h must be on the include path too.)
#include <stdio.h>
#include <stdlib.h>
#include "smartpack_proto.h"
#include "smartpack_key.h"
#include "smartpack_pack.h"

static int fails = 0;
#define CHECK(cond, msg) do { bool ok_ = (cond); printf("%s  %s\n", ok_ ? "PASS" : "FAIL", msg); if (!ok_) fails++; } while (0)

// ---- Cube side model -------------------------------------------------------------------
struct Challenge { uint8_t nonce[8]; uint8_t info[16]; };

// pack serves a challenge: stores the nonce, answers over its current record
static void pack_serve(SmartPackState &p, const uint8_t nonce[8], bool tamper, uint8_t resp[8])
{
    memcpy(p.nonce, nonce, 8);
    p.nonce_valid = true;
    uint8_t info[16];
    smartpack_build_info(p.rec, info);
    smartpack_compute_response(SMARTPACK_KEY, p.nonce, info, resp);
    if (tamper) resp[0] ^= 1;
}

// Cube: read the record, send a nonce, verify the response
static bool cube_challenge(SmartPackState &p, bool tamper, Challenge &ch)
{
    smartpack_build_info(p.rec, ch.info);                       // INFO register read
    for (int i = 0; i < 8; i++) ch.nonce[i] = (uint8_t)rand();   // fresh nonce
    uint8_t resp[8], want[8];
    pack_serve(p, ch.nonce, tamper, resp);
    smartpack_compute_response(SMARTPACK_KEY, ch.nonce, ch.info, want);
    return memcmp(resp, want, 8) == 0;
}

// pack receives a USE write (the three-step handling used by the Nano sketch)
static bool pack_use(SmartPackState &live, const uint8_t mac[8])
{
    SmartPackState snap = live;
    if (!smartpack_use_check(SMARTPACK_KEY, snap, mac)) return false;
    return smartpack_use_commit(live, snap);
}

static void cube_use_mac(const Challenge &ch, uint8_t mac[8])
{
    smartpack_compute_use_mac(SMARTPACK_KEY, ch.nonce, ch.info, mac);
}

int main()
{
    srand(12345);

    // the value the Nano prints as "self-test response" at boot
    {
        SmartPackRecord t = {0x1234, 100, 20261030UL, 0, 500};
        uint8_t n[8] = {0,1,2,3,4,5,6,7}, info[16], r[8];
        smartpack_build_info(t, info);
        smartpack_compute_response(SMARTPACK_KEY, n, info, r);
        printf("Nano self-test response should be: ");
        for (int i = 0; i < 8; i++) printf("%02X", r[i]);
        printf("\n\n");
    }

    SmartPackState p = {};
    p.rec = {0x1234, 100, 20261030UL, 0, 3};
    Challenge ch;

    CHECK(cube_challenge(p, false, ch), "genuine pack passes the challenge");
    CHECK(smartpack_le16(&ch.info[0]) == 0x1234 && smartpack_le32(&ch.info[2]) == 100 &&
          smartpack_le32(&ch.info[6]) == 20261030UL && smartpack_le16(&ch.info[10]) == 0 &&
          smartpack_le16(&ch.info[12]) == 3, "INFO fields round-trip (serial, set, date, count, max)");
    CHECK(!cube_challenge(p, true, ch), "tampered response is rejected");

    // one use
    CHECK(cube_challenge(p, false, ch), "challenge before a use");
    uint8_t mac[8]; cube_use_mac(ch, mac);
    CHECK(pack_use(p, mac) && p.rec.count == 1, "valid USE counts one use");
    CHECK(!pack_use(p, mac) && p.rec.count == 1, "replaying the same USE does nothing");

    // forged / stale reports
    CHECK(cube_challenge(p, false, ch), "next challenge");
    uint8_t bad[8]; cube_use_mac(ch, bad); bad[3] ^= 0x10;
    CHECK(!pack_use(p, bad) && p.rec.count == 1, "forged USE MAC is rejected");
    Challenge stale = ch;
    smartpack_build_info(p.rec, stale.info); stale.info[10] = 0;     // cube believes count is 0
    uint8_t smac[8]; cube_use_mac(stale, smac);
    CHECK(!pack_use(p, smac) && p.rec.count == 1, "USE computed over a stale record is rejected");

    // a newer challenge invalidates the older one
    Challenge c1, c2;
    CHECK(cube_challenge(p, false, c1), "challenge 1");
    CHECK(cube_challenge(p, false, c2), "challenge 2 (replaces 1)");
    uint8_t m1[8]; cube_use_mac(c1, m1);
    CHECK(!pack_use(p, m1) && p.rec.count == 1, "USE for an older challenge is rejected");
    uint8_t m2[8]; cube_use_mac(c2, m2);
    CHECK(pack_use(p, m2) && p.rec.count == 2, "USE for the current challenge counts");

    // a challenge that arrives between check and commit
    {
        CHECK(cube_challenge(p, false, ch), "challenge for the race test");
        uint8_t mm[8]; cube_use_mac(ch, mm);
        SmartPackState snap = p;
        bool ok = smartpack_use_check(SMARTPACK_KEY, snap, mm);
        uint8_t other[8] = {9,9,9,9,9,9,9,9}; uint8_t r[8];
        pack_serve(p, other, false, r);                               // new challenge in between
        CHECK(ok && !smartpack_use_commit(p, snap) && p.rec.count == 2, "commit refused if a new challenge arrived meanwhile");
    }

    // exhaustion
    CHECK(cube_challenge(p, false, ch), "challenge");
    cube_use_mac(ch, mac);
    CHECK(pack_use(p, mac) && p.rec.count == 3, "third use counted");
    uint8_t info[16]; smartpack_build_info(p.rec, info);
    CHECK((info[14] & SMARTPACK_FLAG_EXHAUSTED) != 0, "pack reports EXHAUSTED once count >= max");

    // unprovisioned pack
    SmartPackState u = {};
    uint8_t zero[16] = {0}; smartpack_build_info(u.rec, info);
    CHECK(memcmp(info, zero, 16) == 0, "unprovisioned pack reports an all-zero record");
    CHECK(cube_challenge(u, false, ch), "unprovisioned pack still answers the challenge correctly");
    cube_use_mac(ch, mac);
    CHECK(!pack_use(u, mac) && u.rec.count == 0, "unprovisioned pack never counts uses");

    // wrong key
    {
        uint8_t k2[16]; memcpy(k2, SMARTPACK_KEY, 16); k2[0] ^= 0xFF;
        SmartPackState q = {}; q.rec = {7, 1, 20260101UL, 0, 10};
        uint8_t n[8] = {1,2,3,4,5,6,7,8}, inf[16], resp[8], want[8];
        smartpack_build_info(q.rec, inf);
        smartpack_compute_response(k2, n, inf, resp);
        smartpack_compute_response(SMARTPACK_KEY, n, inf, want);
        CHECK(memcmp(resp, want, 8) != 0, "a pack with a different key fails authentication");
    }

    printf("\n%s (%d failure%s)\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
