#pragma once

// Platform-independent part of the pack authenticator: scanning, challenge/response, use counting,
// the pack policy and the signed pack count. It has no PX4 includes, so the very same file is
// compiled into the firmware and into the host simulator (tools/sim). pack_auth.cpp binds it to
// PX4 (I2C, parameters, uORB).

#include <stdint.h>
#include <stddef.h>

#include "pack_auth_config.h"
#include "pack_auth_reasons.h"

namespace pack_auth
{

// one I2C slave (a pack)
class Link
{
public:
	virtual ~Link() {}
	virtual bool read_regs(uint8_t reg, uint8_t *buf, uint32_t len) = 0;   // write reg, repeated start, read len
	virtual bool write(const uint8_t *buf, uint32_t len) = 0;
};

struct Config {
	int8_t   bus = -1;        // -1 = scan every external bus
	uint8_t  addr = 0x0B;     // address of pack 1; pack N = addr + N - 1
	uint8_t  num = 1;         // packs that must authenticate
	uint16_t sig[4] = {0, 0, 0, 0};   // signature of num for this autopilot
};

// everything the core needs from the platform
class Host
{
public:
	virtual ~Host() {}
	virtual uint32_t millis() = 0;
	virtual void sleep_ms(uint32_t ms) = 0;
	virtual void heartbeat() {}                                   // called often: publish status
	virtual Link *open_link(int8_t bus, uint8_t addr) = 0;        // nullptr if the bus does not exist; the core deletes it
	virtual uint8_t scan_buses(int8_t *buses, uint8_t max) = 0;   // buses to scan when Config::bus = -1
	virtual void fill_random(uint8_t *buf, uint8_t len) = 0;
	virtual bool unique_id(uint8_t id[12]) = 0;                   // this autopilot's unique id
	virtual bool armed() = 0;
	virtual void user_message(const char *text) = 0;                      // user message
	virtual Config get_config() = 0;
};

struct Pack {
	Link    *dev = nullptr;
	bool     ok = false;
	uint32_t ok_ms = 0;
	uint32_t last_scan_ms = 0;
	uint32_t last_try_ms = 0;
	uint16_t ok_serial = 0;
	int32_t  serial = -1;
	int8_t   bus_found = -1;
	uint8_t  last_status = 0xFF;
	uint8_t  why = PKA_R_STARTING;
	uint32_t set_id = 0, activated = 0;   // from the pack's authenticated record
	uint16_t count = 0, max_count = 0;
	bool     use_pending = false;         // a finished flight still has to be reported to the pack
	uint16_t use_base = 0;                // pack count when that flight began
	uint8_t  use_tries = 0;
	uint16_t n_sent = 0, n_ok = 0, n_bad = 0, n_xfer_fail = 0, n_timeout = 0, n_scans = 0;
};

struct Gate {
	bool    open = false;
	uint8_t reason = PKA_R_STARTING;
	uint8_t pack = 0;                     // 1-based slot the reason is about, 0 = whole system
};

class Core
{
public:
	explicit Core(Host &host);
	~Core();
	Core(const Core &) = delete;
	Core &operator=(const Core &) = delete;

	// one pass of the authenticator loop; the caller sleeps ~100 ms between passes
	void run_once();

	// the arming gate as of now: open only if every required pack has a fresh, valid proof
	// (and, in signed builds, the pack count is signed for this autopilot)
	Gate gate() const;

	uint8_t num_required() const;
	bool detect_mode() const;             // signed build and the count is not (validly) signed
	const Pack &pack(uint8_t i) const { return _pack[i]; }
	uint32_t uses_reported() const { return _uses_reported; }

private:
	void step(uint8_t i);
	void find_device(uint8_t i);
	bool probe(Link *d);
	void challenge(uint8_t i);
	void report_detect();
	bool cfg_valid() const;
	bool config_ok(uint8_t n) const;

	Host &_h;
	Pack _pack[PACK_AUTH_MAX_PACKS];
	bool _announced = false;
	bool _started = false;
	bool _was_armed = false;
	uint32_t _arm_start_ms = 0;
	uint32_t _detect_ms = 0;
	uint32_t _uses_reported = 0;
};

}  // namespace pack_auth
