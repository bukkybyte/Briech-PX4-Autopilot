// Runs the REAL pack_auth_core.cpp (the same file the firmware compiles) against simulated packs
// that run the REAL pack-side code of the Nano sketch (smartpack_pack.h), with a fake clock.
// Also runs the real consumer-side gate (pack_auth_gate.h) that Commander uses.
//
//   sim_test <sig-for-1-pack: 4 words> <sig-for-2-packs: 4 words>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <functional>
#include <string>
#include <vector>

#include "smartpack_proto.h"
#include "smartpack_key.h"
#include "smartpack_pack.h"
#include "pack_auth_core.hpp"
#include "pack_auth_gate.h"

using namespace pack_auth;

static int fails = 0;
#define CHECK(cond, msg) do { bool ok_ = (cond); printf("  %s  %s\n", ok_ ? "PASS" : "FAIL", msg); if (!ok_) fails++; } while (0)

static uint32_t now_ms = 5000;                  // the clock the core sees
static bool armed = false;
static std::function<void()> on_tick;           // scenario script, called whenever time advances
static std::vector<std::string> messages;
static uint32_t transfers_while_armed = 0;

// ---- a simulated Nano pack at one I2C address -----------------------------------------------
struct SimPack {
	SmartPackState st;
	bool present = true;
	bool tamper = false;           // answers with a wrong MAC
	uint8_t status = SMARTPACK_ST_IDLE;
	uint8_t response[8] = {0};
	bool busy_pending = false;
	int uses_counted = 0;

	bool read_regs(uint8_t reg, uint8_t *buf, uint32_t len)
	{
		if (armed) { transfers_while_armed++; }
		if (!present) { return false; }
		memset(buf, 0, len);
		if (reg == SMARTPACK_REG_STATUS) {
			if (busy_pending) {                       // the pack's loop() finishes hashing
				uint8_t info[16];
				smartpack_build_info(st.rec, info);
				smartpack_compute_response(SMARTPACK_KEY, st.nonce, info, response);
				if (tamper) { response[0] ^= 1; }
				status = SMARTPACK_ST_READY;
				busy_pending = false;
				buf[0] = SMARTPACK_ST_BUSY;           // the first poll still sees BUSY
			} else {
				buf[0] = status;
			}
		} else if (reg == SMARTPACK_REG_RESPONSE) {
			memcpy(buf, response, len < 8 ? len : 8);
		} else if (reg == SMARTPACK_REG_INFO) {
			uint8_t info[16];
			smartpack_build_info(st.rec, info);
			memcpy(buf, info, len < 16 ? len : 16);
		}
		return true;
	}
	bool write(const uint8_t *p, uint32_t n)
	{
		if (armed) { transfers_while_armed++; }
		if (!present) { return false; }
		if (p[0] == SMARTPACK_REG_NONCE && n == 9) {
			memcpy(st.nonce, p + 1, 8);
			st.nonce_valid = true;
			status = SMARTPACK_ST_BUSY;
			busy_pending = true;
		} else if (p[0] == SMARTPACK_REG_USE && n == 9) {
			SmartPackState snap = st;
			if (smartpack_use_check(SMARTPACK_KEY, snap, p + 1) && smartpack_use_commit(st, snap)) {
				uses_counted++;
			}
		}
		return true;
	}
};

struct LinkRef : Link {            // the core owns (deletes) this, not the pack
	SimPack *p;
	explicit LinkRef(SimPack *p_) : p(p_) {}
	bool read_regs(uint8_t r, uint8_t *b, uint32_t l) override { return p ? p->read_regs(r, b, l) : false; }
	bool write(const uint8_t *b, uint32_t l) override { return p ? p->write(b, l) : false; }
};

static SimPack packs[5];
static const int PACK_BUS = 2;                 // the packs hang on bus 2; bus 1 has nothing

struct SimHost : Host {
	Config cfg;
	uint32_t millis() override { return now_ms; }
	void sleep_ms(uint32_t ms) override { now_ms += ms; if (on_tick) { on_tick(); } }
	Link *open_link(int8_t bus, uint8_t addr) override
	{
		if (bus < 1 || bus > 2) { return nullptr; }
		const int slot = (int)addr - 0x0B;
		if (bus == PACK_BUS && slot >= 0 && slot < 5) { return new LinkRef(&packs[slot]); }
		return new LinkRef(nullptr);          // nothing at this address
	}
	uint8_t scan_buses(int8_t *b, uint8_t) override { b[0] = 1; b[1] = 2; return 2; }
	void fill_random(uint8_t *b, uint8_t n) override { for (uint8_t i = 0; i < n; i++) { b[i] = (uint8_t)rand(); } }
	bool unique_id(uint8_t id[12]) override { for (uint8_t i = 0; i < 12; i++) { id[i] = i; } return true; }
	bool armed() override { return ::armed; }
	void user_message(const char *t) override { messages.push_back(t); printf("      [t=%6.1fs] %s\n", (now_ms - 5000) / 1000.0, t); }
	Config get_config() override { return cfg; }
};

static uint16_t SIG1[4], SIG2[4];

static void reset_world(uint8_t num)
{
	now_ms = 5000; armed = false; on_tick = nullptr; messages.clear(); transfers_while_armed = 0;
	for (int i = 0; i < 5; i++) {
		packs[i] = SimPack();
		packs[i].st.rec = {(uint16_t)(1000 + i), 100, 20261031UL, 2, 500};
	}
	(void)num;
}

static void set_sig(Config &c, uint8_t num)
{
	c.num = num;
	const uint16_t *s = (num == 1) ? SIG1 : SIG2;
	for (int i = 0; i < 4; i++) { c.sig[i] = s[i]; }
}

static void run_for(Core &core, SimHost &h, uint32_t ms)
{
	const uint32_t end = now_ms + ms;
	while (now_ms < end) { core.run_once(); h.sleep_ms(100); }
}

static bool has_msg(const char *needle)
{
	for (auto &m : messages) { if (m.find(needle) != std::string::npos) { return true; } }
	return false;
}

// ------------------------------------------------------------------------------------------------
static void scenario_flights()
{
	printf("\n[flights] PACK_AUTH_MIN_FLIGHT_S=%d: a 5 s and a 40 s flight\n", PACK_AUTH_MIN_FLIGHT_S);
	reset_world(1);
	SimHost h; h.cfg.bus = -1; h.cfg.addr = 0x0B; set_sig(h.cfg, 1);
	Core core(h);
	CHECK(core.gate().reason == PKA_R_STARTING && !core.gate().open, "gate is closed before the first pass (starting)");
	const uint32_t t0 = now_ms;
	bool f1a = false, f1d = false, f2a = false, f2d = false;
	on_tick = [&]() {
		const uint32_t t = now_ms - t0;
		if (!f1a && t >= 10000) { armed = true; f1a = true; }
		if (f1a && !f1d && t >= 15000) { armed = false; f1d = true; }
		if (!f2a && t >= 25000) { armed = true; f2a = true; }
		if (f2a && !f2d && t >= 65000) { armed = false; f2d = true; }
	};
	run_for(core, h, 5000);
	Gate g = core.gate();
	CHECK(g.open && g.reason == PKA_R_OK, "genuine pack found by scanning buses 1 and 2: gate open");
	CHECK(core.pack(0).bus_found == PACK_BUS, "found on bus 2");
	run_for(core, h, 80000 - 5000);
	const int expect_total = (PACK_AUTH_MIN_FLIGHT_S == 0) ? 2 : 1;
	CHECK(packs[0].uses_counted == expect_total, PACK_AUTH_MIN_FLIGHT_S == 0 ? "both flights counted (0 s minimum)" : "only the 40 s flight counted (30 s rule)");
	CHECK(packs[0].st.rec.count == 2 + expect_total, "pack count rose by the counted flights, exactly once each");
	CHECK(transfers_while_armed == 0, "no bus traffic while armed");
	CHECK(core.gate().open, "gate open again after the last flight");
}

static void scenario_pack_faults()
{
	printf("\n[faults] tamper, unplug, unprovisioned, life used up, pack swap\n");
	reset_world(1);
	SimHost h; h.cfg.bus = PACK_BUS; h.cfg.addr = 0x0B; set_sig(h.cfg, 1);
	Core core(h);
	run_for(core, h, 5000);
	CHECK(core.gate().open, "fixed bus: gate open");

	packs[0].tamper = true;
	run_for(core, h, 5000);
	Gate g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_WRONG_RESPONSE && g.pack == 1, "counterfeit/wrong-key answer: closed, wrong response, pack 1");
	packs[0].tamper = false;
	run_for(core, h, 5000);
	CHECK(core.gate().open, "genuine again: reopens");

	packs[0].present = false;
	run_for(core, h, 3000);
	CHECK(!core.gate().open, "unplugged pack: gate closes (within seconds)");
	g = core.gate();
	CHECK(g.pack == 1 && (g.reason == PKA_R_NO_ANSWER || g.reason == PKA_R_STALE), "reason names pack 1 / no answer");
	packs[0].present = true;
	run_for(core, h, 5000);
	CHECK(core.gate().open, "replugged: reopens");

	// the authenticator task stalls: no passes at all, the last proof just ages
	now_ms = core.pack(0).ok_ms + 7000;          // exactly 7 s after the last good answer
	CHECK(core.gate().open, "proof 7 s old: still accepted");
	now_ms += 2000;                               // 9 s
	g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_STALE && g.pack == 1, "proof older than 8 s (task stalled): closed, stale");
	run_for(core, h, 4000);
	CHECK(core.gate().open, "task running again: reopens");

	uint16_t old_serial = packs[0].st.rec.serial;
	packs[0].st.rec.serial = 4321;
	run_for(core, h, 5000);
	CHECK(core.gate().open && core.pack(0).serial == 4321 && old_serial != 4321, "swapped pack (new serial) is re-proven");

	SmartPackRecord keep = packs[0].st.rec;
	packs[0].st.rec = {0, 0, 0, 0, 0};
	run_for(core, h, 5000);
	g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_NOT_PROVISIONED, "unprovisioned pack: closed");
	packs[0].st.rec = keep;
	packs[0].st.rec.count = packs[0].st.rec.max_count;
	run_for(core, h, 5000);
	g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_LIFE_USED_UP, "count >= max_count: life used up");
}

static void scenario_sets()
{
	printf("\n[sets] two packs, signed count for 2\n");
	reset_world(2);
	SimHost h; h.cfg.bus = -1; h.cfg.addr = 0x0B; set_sig(h.cfg, 2);
	Core core(h);
	run_for(core, h, 8000);
	CHECK(core.gate().open, "two genuine packs of one set: open");
	packs[1].st.rec.set_id = 999;
	run_for(core, h, 5000);
	Gate g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_OTHER_SET && g.pack == 2, "pack 2 from another set: closed, other set, pack 2");
	packs[1].st.rec.set_id = 100;
	packs[1].present = false;
	run_for(core, h, 12000);
	g = core.gate();
	CHECK(!g.open && g.pack == 2, "pack 2 missing: closed, names pack 2");
}

static void scenario_signature()
{
	printf("\n[signature] pack count must be signed for this autopilot\n");
	reset_world(2);
	SimHost h; h.cfg.bus = -1; h.cfg.addr = 0x0B; set_sig(h.cfg, 1);
	h.cfg.num = 2;                                  // someone edits PKA_NUM, keeps the old signature
	Core core(h);
	run_for(core, h, 15000);
	Gate g = core.gate();
	CHECK(!g.open && g.reason == PKA_R_COUNT_NOT_SIGNED, "edited count with a stale signature: closed, not signed");
	CHECK(core.detect_mode(), "module is in detect mode");
	CHECK(has_msg("count not signed, detecting"), "announces detect mode");
	CHECK(has_msg("2 pack(s) detected") || has_msg("5 pack(s) detected"), "reports the packs it found");
	CHECK(has_msg("cfg-id: 000102030405060708090a0b"), "prints the cfg-id to sign");
	Config c = h.cfg;
	set_sig(c, 2);
	h.cfg = c;
	run_for(core, h, 5000);
	CHECK(core.gate().open, "correct signature for 2 packs: open");
	h.cfg.sig[2] ^= 1;
	CHECK(!core.gate().open && core.gate().reason == PKA_R_COUNT_NOT_SIGNED, "one flipped signature bit: closed at once");
	reset_world(1);
	SimHost h2; h2.cfg.bus = PACK_BUS; h2.cfg.addr = 0x7F; set_sig(h2.cfg, 1);
	Core core2(h2);
	run_for(core2, h2, 3000);
	CHECK(!core2.gate().open && core2.gate().reason == PKA_R_BAD_ADDR_CONFIG, "address past 0x77: closed, bad config");
}

struct FakeStatus {          // the fields of pack_auth_status_s the gate reads
	uint64_t timestamp; bool gate_open; uint8_t gate_reason; uint8_t gate_pack; uint8_t num_required;
};

static void scenario_consumer_gate()
{
	printf("\n[consumer] Commander-side gate on the published status (fail closed)\n");
	FakeStatus s = {1000000, true, 0, 0, 1};
	PackAuthGateResult r = pack_auth_gate_evaluate(false, s, 1000000);
	CHECK(!r.open && r.reason == PKA_R_NOT_RUNNING, "never published: closed (not running)");
	r = pack_auth_gate_evaluate(true, s, 1500000);
	CHECK(r.open, "fresh and open: open");
	r = pack_auth_gate_evaluate(true, s, 1000000 + PKA_STATUS_MAX_AGE_US + 1);
	CHECK(!r.open && r.reason == PKA_R_STALLED, "status older than 2 s: closed (stalled)");
	r = pack_auth_gate_evaluate(true, s, 500000);
	CHECK(!r.open, "timestamp from the future: closed");
	s.num_required = 0;
	CHECK(!pack_auth_gate_evaluate(true, s, 1000100).open, "open flag with zero required packs: closed");
	s.num_required = 1; s.gate_open = false; s.gate_reason = PKA_R_WRONG_RESPONSE; s.gate_pack = 2;
	r = pack_auth_gate_evaluate(true, s, 1000100);
	CHECK(!r.open && r.reason == PKA_R_WRONG_RESPONSE && r.pack == 2, "reason and slot are passed through");
	s.gate_reason = PKA_R_OK;
	r = pack_auth_gate_evaluate(true, s, 1000100);
	CHECK(!r.open, "closed flag with reason ok: still closed");
}

int main(int argc, char **argv)
{
	if (argc != 9) { fprintf(stderr, "usage: sim_test <4 sig words for 1 pack> <4 sig words for 2 packs>\n"); return 2; }
	for (int i = 0; i < 4; i++) { SIG1[i] = (uint16_t)atoi(argv[1 + i]); SIG2[i] = (uint16_t)atoi(argv[5 + i]); }
	srand(7);
	printf("PACK_AUTH_MIN_FLIGHT_S = %d, PACK_AUTH_CFG_SIGNED = %d\n", PACK_AUTH_MIN_FLIGHT_S, PACK_AUTH_CFG_SIGNED);
	scenario_flights();
	scenario_pack_faults();
	scenario_sets();
	scenario_signature();
	scenario_consumer_gate();
	printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL SIM TESTS PASSED");
	return fails ? 1 : 0;
}

#include "pack_auth_core.cpp"
