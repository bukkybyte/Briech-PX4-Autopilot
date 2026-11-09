#include "pack_auth_core.hpp"

#include <stdio.h>
#include <string.h>

#include "smartpack_proto.h"
#if __has_include("smartpack_key.h")
#include "smartpack_key.h"
#else
#error "Copy smartpack_key.h.example to smartpack_key.h (bash setup.sh key) before building pack_auth"
#endif

namespace pack_auth
{

Core::Core(Host &host) : _h(host) {}

Core::~Core()
{
	for (uint8_t i = 0; i < PACK_AUTH_MAX_PACKS; i++) {
		delete _pack[i].dev;
		_pack[i].dev = nullptr;
	}
}

static inline int16_t clamp16(int16_t v, int16_t lo, int16_t hi) { return v < lo ? lo : (v > hi ? hi : v); }

uint8_t Core::num_required() const
{
	return (uint8_t)clamp16(_h.get_config().num, PACK_AUTH_NUM_MIN, PACK_AUTH_MAX_PACKS);
}

bool Core::config_ok(uint8_t n) const
{
	const unsigned a = _h.get_config().addr;
	return a >= 0x08 && (a + n - 1) <= 0x77;     // 0x00..0x07 are reserved, 0x78+ too
}

#if PACK_AUTH_CFG_SIGNED
// SipHash-2-4(key, 0xC1 || count || autopilot unique id), compared with the four signature
// parameters. Made off-line by tools/sign_config.py.
bool Core::cfg_valid() const
{
	const Config c = _h.get_config();

	if (c.num < 1 || c.num > PACK_AUTH_MAX_PACKS) {
		return false;
	}

	uint8_t uid[12] {};

	if (!_h.unique_id(uid)) {
		return false;
	}

	uint8_t msg[2 + sizeof(uid)];
	msg[0] = 0xC1;                          // keeps this MAC apart from pack responses
	msg[1] = c.num;
	memcpy(&msg[2], uid, sizeof(uid));
	const uint64_t mac = smartpack_siphash24(SMARTPACK_KEY, msg, sizeof(msg));

	uint16_t diff = 0;

	for (uint8_t i = 0; i < 4; i++) {
		diff |= (uint16_t)(((mac >> (16 * i)) & 0xFFFF) ^ c.sig[i]);
	}

	return diff == 0;
}

bool Core::detect_mode() const { return !cfg_valid(); }

// tell the installer how many genuine packs answered, plus the id to sign
void Core::report_detect()
{
	uint8_t found = 0;                      // slots must be contiguous from slot 1

	while (found < PACK_AUTH_MAX_PACKS && _pack[found].ok) {
		found++;
	}

	char hex[2 * 12 + 1] {};
	uint8_t uid[12] {};

	if (_h.unique_id(uid)) {
		for (uint8_t i = 0; i < sizeof(uid); i++) {
			snprintf(&hex[2 * i], 3, "%02x", uid[i]);
		}
	}

	char line[64];
	snprintf(line, sizeof(line), "PackAuth: %u pack(s) detected", (unsigned)found);
	_h.user_message(line);
	snprintf(line, sizeof(line), "PackAuth cfg-id: %s", hex);
	_h.user_message(line);
}
#else
bool Core::cfg_valid() const { return true; }
bool Core::detect_mode() const { return false; }
void Core::report_detect() {}
#endif

Gate Core::gate() const
{
	Gate g;
	const uint8_t n = num_required();

	if (!_started) {
		g.reason = PKA_R_STARTING;
		return g;
	}

	if (!config_ok(n)) {
		g.reason = PKA_R_BAD_ADDR_CONFIG;
		return g;
	}

#if PACK_AUTH_CFG_SIGNED

	if (!cfg_valid()) {
		g.reason = PKA_R_COUNT_NOT_SIGNED;
		return g;
	}

#endif

	const uint32_t now = _h.millis();

	for (uint8_t i = 0; i < n; i++) {
		const Pack &p = _pack[i];

		if (p.ok && (now - p.ok_ms) < PKA_FRESH_MS) {
			continue;
		}

		g.reason = p.ok ? (uint8_t)PKA_R_STALE : p.why;
		g.pack = i + 1;
		return g;
	}

	// packs of different sets must not be mixed
	for (uint8_t i = 1; i < n; i++) {
		if (_pack[i].set_id != _pack[0].set_id) {
			g.reason = PKA_R_OTHER_SET;
			g.pack = i + 1;
			return g;
		}
	}

	g.open = true;
	g.reason = PKA_R_OK;
	return g;
}

void Core::run_once()
{
	char line[64];

	if (!_announced) {
		_announced = true;

		if (detect_mode()) {
			_h.user_message("PackAuth: count not signed, detecting");

		} else {
			snprintf(line, sizeof(line), "PackAuth: %u pack(s) required", (unsigned)num_required());
			_h.user_message(line);
		}
	}

	_h.heartbeat();

	// a flight is "valid" if the vehicle stayed armed long enough; count it on disarm
	const bool armed_now = _h.armed();

	if (armed_now && !_was_armed) {
		_arm_start_ms = _h.millis();

	} else if (!armed_now && _was_armed &&
		   (_h.millis() - _arm_start_ms) >= (uint32_t)PACK_AUTH_MIN_FLIGHT_S * 1000U) {
		const uint8_t np = num_required();

		for (uint8_t k = 0; k < np; k++) {
			_pack[k].use_base = _pack[k].count;
			_pack[k].use_tries = 0;
			_pack[k].use_pending = true;
		}
	}

	_was_armed = armed_now;

	const bool detect = detect_mode();
	const uint8_t n = detect ? PACK_AUTH_MAX_PACKS : num_required();

	if (config_ok(n)) {
		for (uint8_t i = 0; i < n; i++) {
			step(i);
			_h.heartbeat();
		}
	}

	_started = true;

	if (detect && !_h.armed() && (_h.millis() - _detect_ms) > PKA_DETECT_MS) {
		_detect_ms = _h.millis();
		report_detect();
	}

	_h.heartbeat();
}

void Core::step(uint8_t i)
{
	if (_h.armed()) {
		return;                               // never touch the bus while armed
	}

	Pack &p = _pack[i];
	const uint32_t now = _h.millis();

	if (!p.dev) {
		if (now - p.last_scan_ms < PKA_SCAN_MS) {
			return;
		}

		p.last_scan_ms = now;
		find_device(i);

		if (!p.dev) {
			p.why = PKA_R_NOT_FOUND;
			return;
		}
	}

	if (p.ok) {
		if (now - p.ok_ms > PKA_FRESH_MS) {
			p.ok = false;                     // proof went stale
			p.why = PKA_R_STOPPED_ANSWERING;

		} else if (!p.use_pending && now - p.ok_ms < PKA_REAUTH_MS) {
			return;                           // proven recently
		}
	}

	if (now - p.last_try_ms < PKA_RETRY_MS) {
		return;
	}

	p.last_try_ms = now;
	challenge(i);
}

void Core::find_device(uint8_t i)
{
	Pack &p = _pack[i];
	const Config c = _h.get_config();
	const uint8_t addr = (uint8_t)(c.addr + i);

	if (c.bus >= 0) {
		// fixed bus: trust the setting, the challenge shows if nothing answers
		p.dev = _h.open_link(c.bus, addr);
		p.bus_found = p.dev ? c.bus : -1;
		return;
	}

	int8_t buses[8];
	const uint8_t nb = _h.scan_buses(buses, sizeof(buses));
	p.n_scans++;

	for (uint8_t k = 0; k < nb; k++) {
		Link *d = _h.open_link(buses[k], addr);

		if (!d) {
			continue;
		}

		if (probe(d)) {
			p.dev = d;
			p.bus_found = buses[k];
			return;
		}

		delete d;
	}
}

// does something at this address answer our STATUS register with a valid value?
bool Core::probe(Link *d)
{
	uint8_t st = 0xFF;
	return d->read_regs(SMARTPACK_REG_STATUS, &st, 1) && st <= SMARTPACK_ST_READY;
}

void Core::challenge(uint8_t i)
{
	Pack &p = _pack[i];

	// 1. the pack's record: serial, set, activation date, use count, max count
	uint8_t info[SMARTPACK_INFO_LEN];

	if (!p.dev->read_regs(SMARTPACK_REG_INFO, info, sizeof(info))) {
		p.n_xfer_fail++;
		p.ok = false;
		p.why = PKA_R_NO_ANSWER;
		return;
	}

	const uint16_t serial = smartpack_le16(&info[0]);
	p.serial = serial;

	if (p.ok && serial != p.ok_serial) {
		p.ok = false;                         // a different pack: trust nothing
	}

	// 2. fresh random challenge
	uint8_t nonce[SMARTPACK_NONCE_LEN];
	_h.fill_random(nonce, sizeof(nonce));
	uint8_t pkt[1 + SMARTPACK_NONCE_LEN];
	pkt[0] = SMARTPACK_REG_NONCE;
	memcpy(&pkt[1], nonce, sizeof(nonce));

	if (!p.dev->write(pkt, sizeof(pkt))) {
		p.n_xfer_fail++;
		p.ok = false;
		p.why = PKA_R_NONCE_WRITE;
		return;
	}

	p.n_sent++;

	// 3. wait for READY; the pack never stretches the clock
	uint8_t resp[SMARTPACK_RESPONSE_LEN];
	bool ready = false;
	const uint32_t t0 = _h.millis();

	while (_h.millis() - t0 < PKA_TIMEOUT_MS) {
		_h.sleep_ms(20);
		_h.heartbeat();
		uint8_t st = 0xFF;

		if (!p.dev->read_regs(SMARTPACK_REG_STATUS, &st, 1)) {
			p.n_xfer_fail++;
			continue;
		}

		p.last_status = st;

		if (st == SMARTPACK_ST_READY) {
			ready = p.dev->read_regs(SMARTPACK_REG_RESPONSE, resp, sizeof(resp));

			if (!ready) {
				p.n_xfer_fail++;
			}

			break;
		}
	}

	if (!ready) {
		p.n_timeout++;
		p.ok = false;
		p.why = PKA_R_NOT_RESPONDING;
		return;
	}

	// 4. verify without early exit; the MAC covers the whole record
	uint8_t expected[SMARTPACK_RESPONSE_LEN];
	smartpack_compute_response(SMARTPACK_KEY, nonce, info, expected);
	uint8_t diff = 0;

	for (uint8_t k = 0; k < sizeof(resp); k++) {
		diff |= expected[k] ^ resp[k];
	}

	if (diff != 0) {
		p.ok = false;                         // a wrong answer revokes trust
		p.n_bad++;
		p.why = PKA_R_WRONG_RESPONSE;
		return;
	}

	// genuine pack: its record can be trusted now
	p.set_id = smartpack_le32(&info[2]);
	p.activated = smartpack_le32(&info[6]);
	p.count = smartpack_le16(&info[10]);
	p.max_count = smartpack_le16(&info[12]);

	// 5. a flight has finished: report one use to the pack (authenticated, one-shot)
	if (p.use_pending) {
		char line[48];

		if (p.count > p.use_base) {
			p.use_pending = false;            // the pack counted it
			_uses_reported++;
			snprintf(line, sizeof(line), "Pack %u: use %u/%u", (unsigned)(i + 1),
				 (unsigned)p.count, (unsigned)p.max_count);
			_h.user_message(line);

		} else if (p.use_tries < PKA_USE_TRIES) {
			uint8_t mac[SMARTPACK_USE_LEN];
			smartpack_compute_use_mac(SMARTPACK_KEY, nonce, info, mac);
			uint8_t upkt[1 + SMARTPACK_USE_LEN];
			upkt[0] = SMARTPACK_REG_USE;
			memcpy(&upkt[1], mac, sizeof(mac));

			if (!p.dev->write(upkt, sizeof(upkt))) {
				p.n_xfer_fail++;
			}

			p.use_tries++;

		} else {
			p.use_pending = false;
			snprintf(line, sizeof(line), "Pack %u: use not saved", (unsigned)(i + 1));
			_h.user_message(line);
		}
	}

	// 6. policy on the authenticated record
	if (serial == 0 || p.set_id == 0 || p.max_count == 0) {
		p.ok = false;
		p.why = PKA_R_NOT_PROVISIONED;
		return;
	}

	if (p.count >= p.max_count) {
		p.ok = false;
		p.why = PKA_R_LIFE_USED_UP;
		return;
	}

	const bool was_ok = p.ok;
	p.ok_serial = serial;
	p.ok_ms = _h.millis();
	p.ok = true;
	p.n_ok++;
	p.why = PKA_R_OK;

	if (!was_ok) {
		char line[64];
		snprintf(line, sizeof(line), "Pack %u: #%u set %lu use %u/%u", (unsigned)(i + 1),
			 (unsigned)serial, (unsigned long)p.set_id, (unsigned)p.count, (unsigned)p.max_count);
		_h.user_message(line);
	}
}

}  // namespace pack_auth
