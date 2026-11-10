#include "pack_auth.hpp"

#include <string.h>
#include <px4_platform_common/board_common.h>
#include <px4_platform_common/getopt.h>
#include <px4_platform_common/log.h>
#include <systemlib/mavlink_log.h>
#if defined(CONFIG_CRYPTO_RANDOM_POOL)
#include <px4_random.h>
#endif

#include "pack_auth_gate.h"

using namespace time_literals;

// One pack on the I2C bus, 100 kHz. The pack never stretches the clock.
class PackI2C : public device::I2C, public pack_auth::Link
{
public:
	PackI2C(int bus, uint8_t addr) : device::I2C(DRV_DEVTYPE_UNUSED, MODULE_NAME, bus, addr, 100000)
	{
		_retries = 2;
	}

	bool read_regs(uint8_t reg, uint8_t *buf, uint32_t len) override
	{
		return transfer(&reg, 1, buf, len) == PX4_OK;
	}

	bool write(const uint8_t *buf, uint32_t len) override
	{
		return transfer(buf, len, nullptr, 0) == PX4_OK;
	}
};

#if PACK_AUTH_MODULEBASE_DESC
ModuleBase::Descriptor PackAuth::desc{task_spawn, custom_command, print_usage};
#endif

PackAuth::PackAuth() : ModuleParams(nullptr)
{
	// seed for the nonce generator when the OS has no secure random pool
	uint8_t uid[12] {};
	unique_id(uid);
	_rng = hrt_absolute_time() ^ 0x9E3779B97F4A7C15ULL;

	for (uint8_t i = 0; i < sizeof(uid); i++) {
		_rng = (_rng << 5) ^ (_rng >> 59) ^ uid[i];
	}

	if (_rng == 0) {
		_rng = 0x2545F4914F6CDD1DULL;
	}

	_status_pub.advertise();
}

pack_auth::Link *PackAuth::open_link(int8_t bus, uint8_t addr)
{
	// PX4 numbers I2C buses from 1
	if (bus < 1 || bus > (int8_t)PX4_NUMBER_I2C_BUSES) {
		return nullptr;
	}

	PackI2C *d = new PackI2C(bus, addr);

	if (d == nullptr) {
		return nullptr;
	}

	if (d->init() != PX4_OK) {
		delete d;
		return nullptr;
	}

	return d;
}

uint8_t PackAuth::scan_buses(int8_t *buses, uint8_t max)
{
	uint8_t n = 0;
	I2CBusIterator iter(I2CBusIterator::FilterType::ExternalBus);

	while (n < max && iter.next()) {
		buses[n++] = (int8_t)iter.bus().bus;
	}

	return n;
}

void PackAuth::fill_random(uint8_t *buf, uint8_t len)
{
#if defined(CONFIG_CRYPTO_RANDOM_POOL)

	if (px4_get_secure_random(buf, len) == len) {
		return;
	}

#endif

	// fallback: xorshift64* mixed with the microsecond clock on every draw
	for (uint8_t i = 0; i < len; i++) {
		_rng ^= (uint64_t)hrt_absolute_time() + 0x9E3779B97F4A7C15ULL;
		_rng ^= _rng >> 12;
		_rng ^= _rng << 25;
		_rng ^= _rng >> 27;
		buf[i] = (uint8_t)((_rng * 0x2545F4914F6CDD1DULL) >> 56);
	}
}

bool PackAuth::unique_id(uint8_t id[12])
{
	memset(id, 0, 12);
#if defined(__PX4_NUTTX)
	uuid_byte_t uuid {};
	board_get_uuid(uuid);
	memcpy(id, uuid, sizeof(uuid) < 12 ? sizeof(uuid) : 12);
	return true;
#else
	return false;
#endif
}

bool PackAuth::armed()
{
	_vehicle_status_sub.update();
	return _vehicle_status_sub.get().arming_state == vehicle_status_s::ARMING_STATE_ARMED;
}

void PackAuth::user_message(const char *text)
{
	PX4_INFO("%s", text);

	// the provisioning id is what the operator has to copy: warning severity so QGC pops it up
	// (info lines only go to its message log)
	if (strstr(text, "cfg-id") != nullptr) {
		mavlink_log_warning(&_mavlink_log_pub, "%s\t", text);

	} else {
		mavlink_log_info(&_mavlink_log_pub, "%s\t", text);
	}
}

pack_auth::Config PackAuth::get_config()
{
	pack_auth::Config c;
	c.bus = (int8_t)_param_pka_bus.get();
	c.addr = (uint8_t)_param_pka_addr.get();
	c.num = (uint8_t)_param_pka_num.get();
	c.sig[0] = (uint16_t)_param_pka_s0.get();
	c.sig[1] = (uint16_t)_param_pka_s1.get();
	c.sig[2] = (uint16_t)_param_pka_s2.get();
	c.sig[3] = (uint16_t)_param_pka_s3.get();
	return c;
}

void PackAuth::publish_status(bool force)
{
	const hrt_abstime now = hrt_absolute_time();

	if (!force && (now - _last_publish) < 100_ms) {
		return;
	}

	_last_publish = now;

	const pack_auth::Gate g = _core.gate();
	pack_auth_status_s s{};
	s.timestamp = now;
	s.gate_open = g.open;
	s.gate_reason = g.reason;
	s.gate_pack = g.pack;
	s.num_required = _core.num_required();
	s.detecting = _core.detect_mode();

	for (uint8_t i = 0; i < pack_auth_status_s::MAX_PACKS && i < PACK_AUTH_MAX_PACKS; i++) {
		const pack_auth::Pack &p = _core.pack(i);
		s.pack_ok[i] = p.ok;
		s.pack_reason[i] = p.ok ? (uint8_t)PKA_R_OK : p.why;
		s.serial[i] = p.ok ? (uint16_t)p.serial : 0;
		s.set_id[i] = p.set_id;
		s.activated[i] = p.activated;
		s.use_count[i] = p.count;
		s.max_count[i] = p.max_count;
	}

	_status_pub.publish(s);
}

void PackAuth::run()
{
	while (!should_exit()) {
		if (_parameter_update_sub.updated()) {
			parameter_update_s update;
			_parameter_update_sub.copy(&update);
			updateParams();
		}

		_core.run_once();
		publish_status(true);
		px4_usleep(100_ms);
	}
}

int PackAuth::print_status()
{
	const pack_auth::Gate g = _core.gate();
	if (g.open) {
		PX4_INFO("gate: OPEN");

	} else if (g.pack) {
		PX4_INFO("gate: closed, pack %u: %s", (unsigned)g.pack, pack_auth_reason_str(g.reason));

	} else {
		PX4_INFO("gate: closed, %s", pack_auth_reason_str(g.reason));
	}

	{
		uint8_t uid[12] {};
		char hex[2 * 12 + 1] {};

		if (unique_id(uid)) {
			for (uint8_t i = 0; i < sizeof(uid); i++) {
				snprintf(&hex[2 * i], 3, "%02x", uid[i]);
			}
		}

		PX4_INFO("cfg-id: %s", hex);
	}

	PX4_INFO("required packs: %u%s", (unsigned)_core.num_required(),
		 _core.detect_mode() ? " (count not signed: detect mode)" : "");

	const uint8_t n = _core.detect_mode() ? PACK_AUTH_MAX_PACKS : _core.num_required();

	for (uint8_t i = 0; i < n; i++) {
		const pack_auth::Pack &p = _core.pack(i);
		PX4_INFO("pack %u: %s  bus=%d serial=%ld set=%lu use=%u/%u act=%lu",
			 (unsigned)(i + 1), p.ok ? "ok" : pack_auth_reason_str(p.why), (int)p.bus_found, (long)p.serial,
			 (unsigned long)p.set_id, (unsigned)p.count, (unsigned)p.max_count, (unsigned long)p.activated);
		PX4_INFO("        tx=%u ok=%u bad=%u xfer_fail=%u timeout=%u scans=%u",
			 (unsigned)p.n_sent, (unsigned)p.n_ok, (unsigned)p.n_bad, (unsigned)p.n_xfer_fail,
			 (unsigned)p.n_timeout, (unsigned)p.n_scans);
	}

	PX4_INFO("flights counted this boot: %lu", (unsigned long)_core.uses_reported());
	return 0;
}

#if PACK_AUTH_MODULEBASE_DESC
int PackAuth::run_trampoline(int argc, char *argv[])
{
	return ModuleBase::run_trampoline_impl(desc, [](int ac, char *av[]) -> ModuleBase * {
		return PackAuth::instantiate(ac, av);
	}, argc, argv);
}

int PackAuth::task_spawn(int argc, char *argv[])
{
	desc.task_id = px4_task_spawn_cmd("pack_auth",
					  SCHED_DEFAULT,
					  SCHED_PRIORITY_SLOW_DRIVER,
					  PX4_STACK_ADJUSTED(3000),
					  (px4_main_t)&run_trampoline,
					  (char *const *)argv);

	if (desc.task_id < 0) {
		desc.task_id = -1;
		return -errno;
	}

	if (wait_until_running(desc, 2000) < 0) {
		desc.task_id = -1;
		return -1;
	}

	return 0;
}
#else
int PackAuth::task_spawn(int argc, char *argv[])
{
	_task_id = px4_task_spawn_cmd("pack_auth",
				      SCHED_DEFAULT,
				      SCHED_PRIORITY_SLOW_DRIVER,
				      PX4_STACK_ADJUSTED(3000),
				      (px4_main_t)&run_trampoline,
				      (char *const *)argv);

	if (_task_id < 0) {
		_task_id = -1;
		return -errno;
	}

	if (wait_until_running() < 0) {
		_task_id = -1;
		return -1;
	}

	return 0;
}
#endif

PackAuth *PackAuth::instantiate(int argc, char *argv[])
{
	return new PackAuth();
}

int PackAuth::custom_command(int argc, char *argv[])
{
	return print_usage("unknown command");
}

int PackAuth::print_usage(const char *reason)
{
	if (reason) {
		PX4_WARN("%s\n", reason);
	}

	PRINT_MODULE_DESCRIPTION(
		R"DESCR_STR(
### Description
Battery pack authentication. Every required battery pack must prove it is genuine (SipHash-2-4
challenge/response over I2C, shared 16 byte key) before the vehicle can be armed, and the pack's use
counter is incremented after each flight.

The result is published as `pack_auth_status`; Commander refuses to arm unless the gate is open. The
check cannot be skipped with a forced arm, an arm-on-boot or an RC re-arm grace period.

Parameters: PKA_NUM (number of packs), PKA_ADDR (address of pack 1, pack N = PKA_ADDR + N - 1), PKA_BUS
(-1 scans every external I2C bus), PKA_S0..S3 (signature of PKA_NUM for this autopilot).
)DESCR_STR");

	PRINT_MODULE_USAGE_NAME("pack_auth", "system");
	PRINT_MODULE_USAGE_COMMAND("start");
	PRINT_MODULE_USAGE_DEFAULT_COMMANDS();
	return 0;
}

extern "C" __EXPORT int pack_auth_main(int argc, char *argv[])
{
#if PACK_AUTH_MODULEBASE_DESC
	return ModuleBase::main(PackAuth::desc, argc, argv);
#else
	return PackAuth::main(argc, argv);
#endif
}
