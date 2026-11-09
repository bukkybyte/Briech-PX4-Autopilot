#pragma once

#include "../Common.hpp"

#include <uORB/Subscription.hpp>
#include <uORB/topics/pack_auth_status.h>

/**
 * Battery pack authentication: arming is refused unless the pack_auth module reports an open gate.
 * (Commander::arm() additionally enforces the same gate when preflight checks are skipped.)
 */
class PackAuthChecks : public HealthAndArmingCheckBase
{
public:
	PackAuthChecks() = default;
	~PackAuthChecks() = default;

	void checkAndReport(const Context &context, Report &reporter) override;

private:
	uORB::Subscription _pack_auth_status_sub{ORB_ID(pack_auth_status)};
};
