// SmartPack v2 slave for Arduino Nano (ATmega328P)
// Pretends to be a smart battery on I2C address I2C_ADDR:
//   - standard SBS telemetry registers (voltage, current ...)
//   - challenge/response + pack record + use counter (see smartpack_proto.h)
//
// The pack record (serial, set id, activation date, use count, max count) lives in EEPROM.
// You read it here on the serial monitor, the flight controller reads it over I2C.
//
// Serial monitor (115200, newline) commands:
//   p            print the pack record and state
//   a <addr>     set this pack's I2C address (8..119, decimal), used after a reset
//   n <serial>   set serial number (1..65535)
//   g <set>      set the set id (all packs of one set share it)
//   d <YYYYMMDD> set the activation date
//   m <max>      set the max count (1..65535)
//   c <count>    set the use count (service use / testing)
//   v <mV>       set pack voltage        e.g. v 14800
//   i <mA>       set current (negative = discharging)
//   t            toggle "tamper" (wrong response -> FC must refuse to arm)
//
// Wiring: Nano A4 = SDA, A5 = SCL through the level shifter, GND common with the FC.

#include <Wire.h>
#include <EEPROM.h>
#include "smartpack_proto.h"
#include "smartpack_key.h"
#include "smartpack_pack.h"

static const uint8_t DEFAULT_ADDR = 0x0B;   // used until you set one with the "a" command
static uint8_t g_addr = DEFAULT_ADDR;       // this pack's I2C address, kept in EEPROM

// SBS registers used by the generic Smart Battery (SMBus) battery drivers
static const uint8_t REG_TEMP       = 0x08;
static const uint8_t REG_VOLTAGE    = 0x09;
static const uint8_t REG_CURRENT    = 0x0A;
static const uint8_t REG_REMAIN     = 0x0F;
static const uint8_t REG_FULLCAP    = 0x10;
static const uint8_t REG_CYCLES     = 0x17;
static const uint8_t REG_SPECINFO   = 0x1A;
static const uint8_t REG_SERIAL     = 0x1C;
static const uint8_t REG_CELL_FIRST = 0x34;   // cell1 = 0x3F, cell2 = 0x3E ...
static const uint8_t NUM_CELLS      = 4;

// simulated telemetry
static volatile uint16_t g_voltage_mv = 14800;
static volatile int16_t  g_current_ma = -1500;
static volatile bool     g_tamper = false;

// pack record + last served challenge (shared with the I2C interrupt handlers)
static SmartPackState g;

// protocol state
static volatile uint8_t g_reg = 0;
static volatile uint8_t g_status = SMARTPACK_ST_IDLE;
static volatile bool    g_nonce_pending = false;
static volatile bool    g_use_pending = false;
static uint8_t g_use_mac[SMARTPACK_USE_LEN];
static uint8_t g_response[SMARTPACK_RESPONSE_LEN];

// ---- EEPROM -------------------------------------------------------------------------
static const uint16_t MAGIC = 0x5A70;
struct Stored { uint16_t magic; SmartPackRecord rec; uint8_t crc; };

static uint8_t crc8(const uint8_t *p, uint8_t n)
{
    uint8_t c = 0xFF;
    while (n--) {
        c ^= *p++;
        for (uint8_t i = 0; i < 8; i++) {
            c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x31) : (uint8_t)(c << 1);
        }
    }
    return c;
}

static void saveRecord()
{
    Stored s;
    memset(&s, 0, sizeof(s));
    noInterrupts(); s.rec = g.rec; interrupts();
    s.magic = MAGIC;
    s.crc = crc8((const uint8_t *)&s.rec, sizeof(s.rec));
    EEPROM.put(0, s);                          // writes only the bytes that changed
}

static void loadRecord()
{
    Stored s;
    EEPROM.get(0, s);
    if (s.magic == MAGIC && s.crc == crc8((const uint8_t *)&s.rec, sizeof(s.rec))) {
        g.rec = s.rec;
    } else {
        memset(&g.rec, 0, sizeof(g.rec));      // blank or damaged: not provisioned
    }
}

// the I2C address is stored apart from the record: one byte plus its inverse as a check
static const int ADDR_EE = 32;

static uint8_t loadAddr()
{
    const uint8_t a = EEPROM.read(ADDR_EE);
    const uint8_t n = EEPROM.read(ADDR_EE + 1);
    if ((uint8_t)~a == n && a >= 8 && a <= 119) {
        return a;
    }
    return DEFAULT_ADDR;
}

static void saveAddr(uint8_t a)
{
    EEPROM.update(ADDR_EE, a);
    EEPROM.update(ADDR_EE + 1, (uint8_t)~a);
}

// ---- I2C handlers ---------------------------------------------------------------------
static void put16(uint8_t *b, uint16_t v)
{
    b[0] = v & 0xFF;
    b[1] = v >> 8;
}

// master wrote something: [reg] or [reg, data...]
static void onReceiveHandler(int n)
{
    if (n < 1) {
        return;
    }
    const uint8_t reg = Wire.read();
    g_reg = reg;
    n--;

    if (reg == SMARTPACK_REG_NONCE && n == SMARTPACK_NONCE_LEN) {
        for (uint8_t i = 0; i < SMARTPACK_NONCE_LEN; i++) {
            g.nonce[i] = Wire.read();
        }
        g.nonce_valid = true;
        g_status = SMARTPACK_ST_BUSY;           // never clock-stretch: tell the FC to poll
        g_nonce_pending = true;
        return;
    }
    if (reg == SMARTPACK_REG_USE && n == SMARTPACK_USE_LEN) {
        for (uint8_t i = 0; i < SMARTPACK_USE_LEN; i++) {
            g_use_mac[i] = Wire.read();
        }
        g_use_pending = true;
        return;
    }
    while (n-- > 0) {
        Wire.read();                            // ignore anything else
    }
}

// master wants to read the register selected by the last write
static void onRequestHandler()
{
    uint8_t buf[SMARTPACK_INFO_LEN] = {0};
    uint8_t len = 2;
    const uint8_t reg = g_reg;

    if (reg == SMARTPACK_REG_STATUS) {
        buf[0] = g_status;
        len = 1;
    } else if (reg == SMARTPACK_REG_RESPONSE) {
        if (g_status == SMARTPACK_ST_READY) {
            memcpy(buf, g_response, SMARTPACK_RESPONSE_LEN);
        }
        len = SMARTPACK_RESPONSE_LEN;
    } else if (reg == SMARTPACK_REG_INFO) {
        smartpack_build_info(g.rec, buf);
        len = SMARTPACK_INFO_LEN;
    } else {
        switch (reg) {
        case REG_TEMP:     put16(buf, 2982); break;   // 25.0 C
        case REG_VOLTAGE:  put16(buf, g_voltage_mv); break;
        case REG_CURRENT:  put16(buf, (uint16_t)g_current_ma); break;
        case REG_REMAIN:   put16(buf, 4000); break;
        case REG_FULLCAP:  put16(buf, 5000); break;
        case REG_CYCLES:   put16(buf, g.rec.count); break;
        case REG_SPECINFO: put16(buf, 0x0021); break; // SBS v1.1, no PEC
        case REG_SERIAL:   put16(buf, g.rec.serial); break;
        default:
            if (reg >= REG_CELL_FIRST && reg <= 0x3F) {
                const uint8_t cell = 0x3F - reg;       // 0-based
                if (cell < NUM_CELLS) {
                    put16(buf, g_voltage_mv / NUM_CELLS);
                }
            }
            break;                                      // unknown register -> zeros
        }
    }
    Wire.write(buf, len);
}

// ---- serial monitor -------------------------------------------------------------------
static void printInfo()
{
    SmartPackRecord r;
    noInterrupts(); r = g.rec; interrupts();
    Serial.print(F("addr=0x")); Serial.print(g_addr, HEX);
    Serial.print(F(" serial=")); Serial.print(r.serial);
    Serial.print(F(" set=")); Serial.print(r.set_id);
    Serial.print(F(" activated=")); Serial.print(r.activated);
    Serial.print(F(" use=")); Serial.print(r.count);
    Serial.print('/'); Serial.print(r.max_count);
    Serial.print(smartpack_provisioned(r) ? F("  provisioned") : F("  NOT PROVISIONED"));
    if (smartpack_provisioned(r) && r.count >= r.max_count) {
        Serial.print(F("  EXHAUSTED"));
    }
    Serial.print(F("  V=")); Serial.print(g_voltage_mv);
    Serial.print(F("mV I=")); Serial.print(g_current_ma);
    Serial.print(F("mA tamper=")); Serial.println(g_tamper ? F("ON") : F("off"));
}

static void handleSerial()
{
    if (!Serial.available()) {
        return;
    }
    const char c = Serial.read();
    if (c == 'v') {
        g_voltage_mv = (uint16_t)Serial.parseInt();
    } else if (c == 'i') {
        g_current_ma = (int16_t)Serial.parseInt();
    } else if (c == 't') {
        g_tamper = !g_tamper;
    } else if (c == 'n' || c == 'g' || c == 'd' || c == 'm' || c == 'c') {
        const long v = Serial.parseInt();
        noInterrupts();
        if (c == 'n')      { g.rec.serial = (uint16_t)constrain(v, 0, 65535); }
        else if (c == 'g') { g.rec.set_id = (uint32_t)max(v, 0L); }
        else if (c == 'd') { g.rec.activated = (uint32_t)max(v, 0L); }
        else if (c == 'm') { g.rec.max_count = (uint16_t)constrain(v, 0, 65535); }
        else               { g.rec.count = (uint16_t)constrain(v, 0, 65535); }
        interrupts();
        saveRecord();
    } else if (c == 'a') {
        const long v = Serial.parseInt();
        if (v >= 8 && v <= 119) {
            saveAddr((uint8_t)v);
            Serial.print(F("address saved, reset the board to use ")); Serial.println(v);
        } else {
            Serial.println(F("address must be 8..119"));
        }
        return;
    } else if (c != 'p') {
        return;
    }
    printInfo();
}

// ---- setup / loop ---------------------------------------------------------------------
void setup()
{
    Serial.begin(115200);
    loadRecord();

    // boot self-test: the host test (protocol_test) prints the same value
    // (record 0x1234 / set 100 / 20261030 / 0 / 500, nonce 00..07)
    SmartPackRecord t = {0x1234, 100, 20261030UL, 0, 500};
    uint8_t n[SMARTPACK_NONCE_LEN] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t info[SMARTPACK_INFO_LEN], r[SMARTPACK_RESPONSE_LEN];
    smartpack_build_info(t, info);
    smartpack_compute_response(SMARTPACK_KEY, n, info, r);
    Serial.print(F("self-test response: "));
    for (uint8_t i = 0; i < SMARTPACK_RESPONSE_LEN; i++) {
        if (r[i] < 16) Serial.print('0');
        Serial.print(r[i], HEX);
    }
    Serial.println();

    g_addr = loadAddr();
    Wire.begin(g_addr);
    Wire.onReceive(onReceiveHandler);
    Wire.onRequest(onRequestHandler);
    Serial.print(F("SmartPack slave ready: "));
    printInfo();
}

void loop()
{
    // a new challenge arrived: hash it outside the interrupt
    if (g_nonce_pending) {
        SmartPackState snap;
        noInterrupts();
        snap = g;
        g_nonce_pending = false;
        interrupts();

        uint8_t info[SMARTPACK_INFO_LEN], resp[SMARTPACK_RESPONSE_LEN];
        smartpack_build_info(snap.rec, info);
        smartpack_compute_response(SMARTPACK_KEY, snap.nonce, info, resp);
        if (g_tamper) {
            resp[0] ^= 0x01;
        }
        noInterrupts();
        memcpy(g_response, resp, sizeof(resp));
        if (!g_nonce_pending) {                 // a newer challenge would make this one stale
            g_status = SMARTPACK_ST_READY;
        }
        interrupts();
    }

    // the flight controller reports one use
    if (g_use_pending) {
        SmartPackState snap;
        uint8_t mac[SMARTPACK_USE_LEN];
        noInterrupts();
        snap = g;
        memcpy(mac, g_use_mac, sizeof(mac));
        g_use_pending = false;
        interrupts();

        if (smartpack_use_check(SMARTPACK_KEY, snap, mac)) {
            bool counted;
            noInterrupts();
            counted = smartpack_use_commit(g, snap);
            interrupts();
            if (counted) {
                saveRecord();
                Serial.print(F("use counted: "));
                printInfo();
            }
        } else {
            Serial.println(F("use report rejected"));
        }
    }
    handleSerial();
}
