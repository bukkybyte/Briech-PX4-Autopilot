// Uno test master: acts like the Cube and authenticates up to 5 SmartPack v2 packs.
// Pack N is at BASE_ADDR + N - 1, exactly like the pack_auth module.
// Put smartpack_proto.h (v2) and smartpack_key.h in this sketch folder.
//
// Wiring: Uno A4 = SDA, A5 = SCL to every Nano's A4 / A5 (all on the same two wires),
// GND common. Each Nano needs its OWN I2C address.

#include <Wire.h>
#include "smartpack_proto.h"
#include "smartpack_key.h"

static const uint8_t BASE_ADDR = 0x0B;   // address of pack 1 (= PKA_ADDR on the Cube)
static const uint8_t NUM_PACKS = 1;      // packs to test, 1..5
#define SHIFTER_3V3 0                    // 1 = Uno drives a 3.3 V level shifter: turn off its 5 V pull-ups
#define TEST_USE    0                    // 1 = also report one use to every pack that passes (count +1)

static bool readReg(uint8_t addr, uint8_t reg, uint8_t *buf, uint8_t len)
{
    Wire.beginTransmission(addr);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0) return false;      // repeated start, like the Cube
    if (Wire.requestFrom(addr, len) != len) return false;
    for (uint8_t i = 0; i < len; i++) buf[i] = Wire.read();
    return true;
}

// one full challenge/response against one pack; prints one line, returns true if it passed
static bool testPack(uint8_t slot)
{
    const uint8_t addr = BASE_ADDR + slot;
    Serial.print(F("pack ")); Serial.print(slot + 1);
    Serial.print(F(" @0x")); Serial.print(addr, HEX); Serial.print(F(": "));

    // 1. the pack record (serial, set, date, use count, max count)
    uint8_t info[SMARTPACK_INFO_LEN];
    if (!readReg(addr, SMARTPACK_REG_INFO, info, sizeof(info))) { Serial.println(F("FAIL no answer (info read)")); return false; }
    const uint16_t serial = smartpack_le16(&info[0]);
    const uint16_t count = smartpack_le16(&info[10]);
    Serial.print(F("#")); Serial.print(serial);
    Serial.print(F(" set=")); Serial.print(smartpack_le32(&info[2]));
    Serial.print(F(" date=")); Serial.print(smartpack_le32(&info[6]));
    Serial.print(F(" use=")); Serial.print(count);
    Serial.print('/'); Serial.print(smartpack_le16(&info[12])); Serial.print(' ');

    // 2. random nonce
    uint8_t nonce[SMARTPACK_NONCE_LEN];
    for (uint8_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)random(256);
    Wire.beginTransmission(addr);
    Wire.write(SMARTPACK_REG_NONCE);
    Wire.write(nonce, sizeof(nonce));
    const uint8_t e = Wire.endTransmission();
    if (e != 0) { Serial.print(F("FAIL nonce write err=")); Serial.println(e); return false; }

    // 3. poll status until READY (20 x 20 ms)
    uint8_t st = 0xFF;
    for (uint8_t i = 0; i < 20 && st != SMARTPACK_ST_READY; i++) {
        delay(20);
        readReg(addr, SMARTPACK_REG_STATUS, &st, 1);
    }
    if (st != SMARTPACK_ST_READY) { Serial.print(F("FAIL status=")); Serial.println(st); return false; }

    // 4. response (the MAC covers the whole record)
    uint8_t resp[SMARTPACK_RESPONSE_LEN], want[SMARTPACK_RESPONSE_LEN];
    if (!readReg(addr, SMARTPACK_REG_RESPONSE, resp, sizeof(resp))) { Serial.println(F("FAIL response read")); return false; }
    smartpack_compute_response(SMARTPACK_KEY, nonce, info, want);
    if (memcmp(resp, want, sizeof(resp)) != 0) { Serial.println(F("MISMATCH")); return false; }
    Serial.println(F("OK"));

#if TEST_USE
    // 5. report one use (authenticated with the same challenge), then read the record back
    uint8_t pkt[1 + SMARTPACK_USE_LEN];
    pkt[0] = SMARTPACK_REG_USE;
    smartpack_compute_use_mac(SMARTPACK_KEY, nonce, info, &pkt[1]);
    Wire.beginTransmission(addr);
    Wire.write(pkt, sizeof(pkt));
    Wire.endTransmission();
    delay(100);
    uint8_t after[SMARTPACK_INFO_LEN];
    if (readReg(addr, SMARTPACK_REG_INFO, after, sizeof(after))) {
        Serial.print(F("   use report: count ")); Serial.print(count);
        Serial.print(F(" -> ")); Serial.println(smartpack_le16(&after[10]));
    }
#endif
    return true;
}

void setup()
{
    Serial.begin(115200);
    Wire.begin();
#if SHIFTER_3V3
    pinMode(A4, INPUT);              // disable the internal pull-ups, the shifter provides them
    pinMode(A5, INPUT);
#endif
    Wire.setClock(100000);
    randomSeed(analogRead(A0) ^ micros());
    delay(1000);

    Serial.println(F("scan:"));
    for (uint8_t a = 1; a < 127; a++) {
        Wire.beginTransmission(a);
        if (Wire.endTransmission() == 0) { Serial.print(F(" found 0x")); Serial.println(a, HEX); }
    }
    Serial.print(F("testing ")); Serial.print(NUM_PACKS);
    Serial.print(F(" pack(s) from 0x")); Serial.println(BASE_ADDR, HEX);
}

void loop()
{
    uint8_t ok = 0;
    for (uint8_t slot = 0; slot < NUM_PACKS; slot++) {
        if (testPack(slot)) ok++;
    }
    Serial.print(F("-> ")); Serial.print(ok); Serial.print('/'); Serial.print(NUM_PACKS);
    Serial.println(ok == NUM_PACKS ? F(" all packs OK") : F(" NOT all OK"));
    Serial.println();
    delay(1000);
}
