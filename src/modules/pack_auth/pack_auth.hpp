#pragma once

#include <px4_platform_common/px4_config.h>
#include <px4_platform_common/module.h>
#include <px4_platform_common/module_params.h>
#include <px4_platform_common/i2c.h>
#include <drivers/device/i2c.h>
#include <drivers/drv_hrt.h>
#include <uORB/Publication.hpp>
#include <uORB/Subscription.hpp>
#include <uORB/topics/pack_auth_status.h>
#include <uORB/topics/parameter_update.h>
#include <uORB/topics/vehicle_status.h>

#include "pack_auth_core.hpp"

/**
 * Battery pack authenticator. Runs in its own low-priority task, talks I2C to the packs,
 * and publishes pack_auth_status for the arming gate in Commander.
 */
#if PACK_AUTH_MODULEBASE_DESC
// PX4 main (after the ModuleBase refactor): one Descriptor per module
#define PACK_AUTH_MODULE_BASE ModuleBase
#else
// PX4 v1.17 and older: ModuleBase<T> with static members
#define PACK_AUTH_MODULE_BASE ModuleBase<PackAuth>
#endif

class PackAuth : public PACK_AUTH_MODULE_BASE, public ModuleParams, public pack_auth::Host
{
public:
#if PACK_AUTH_MODULEBASE_DESC
	static Descriptor desc;
#endif

	PackAuth();
	~PackAuth() override = default;

	static int task_spawn(int argc, char *argv[]);
#if PACK_AUTH_MODULEBASE_DESC
	static int run_trampoline(int argc, char *argv[]);
#endif
	static PackAuth *instantiate(int argc, char *argv[]);
	static int custom_command(int argc, char *argv[]);
	static int print_usage(const char *reason = nullptr);

	void run() override;
	int print_status() override;

	// ---- pack_auth::Host ----
	uint32_t millis() override { return (uint32_t)(hrt_absolute_time() / 1000); }
	void sleep_ms(uint32_t ms) override { px4_usleep(ms * 1000U); }
	void heartbeat() override { publish_status(false); }
	pack_auth::Link *open_link(int8_t bus, uint8_t addr) override;
	uint8_t scan_buses(int8_t *buses, uint8_t max) override;
	void fill_random(uint8_t *buf, uint8_t len) override;
	bool unique_id(uint8_t id[12]) override;
	bool armed() override;
	void user_message(const char *text) override;
	pack_auth::Config get_config() override;

private:
	void publish_status(bool force);

	pack_auth::Core _core{*this};

	uORB::Publication<pack_auth_status_s> _status_pub{ORB_ID(pack_auth_status)};
	uORB::Subscription _parameter_update_sub{ORB_ID(parameter_update)};
	uORB::SubscriptionData<vehicle_status_s> _vehicle_status_sub{ORB_ID(vehicle_status)};

	hrt_abstime _last_publish{0};
	uint64_t _rng{0};
	orb_advert_t _mavlink_log_pub{nullptr};

	DEFINE_PARAMETERS(
		(ParamInt<px4::params::PKA_BUS>) _param_pka_bus,
		(ParamInt<px4::params::PKA_ADDR>) _param_pka_addr,
		(ParamInt<px4::params::PKA_NUM>) _param_pka_num,
		(ParamInt<px4::params::PKA_S0>) _param_pka_s0,
		(ParamInt<px4::params::PKA_S1>) _param_pka_s1,
		(ParamInt<px4::params::PKA_S2>) _param_pka_s2,
		(ParamInt<px4::params::PKA_S3>) _param_pka_s3
	)
};
