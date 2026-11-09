#include "packAuthCheck.hpp"

#include <modules/pack_auth/pack_auth_gate.h>

#include <drivers/drv_hrt.h>
#include <px4_platform_common/events.h>

void PackAuthChecks::checkAndReport(const Context &context, Report &reporter)
{
	pack_auth_status_s status{};
	const bool have = _pack_auth_status_sub.copy(&status);
	const PackAuthGateResult r = pack_auth_gate_evaluate(have, status, hrt_absolute_time());

	if (r.open) {
		return;
	}

	switch (r.reason) {
	case PKA_R_NOT_RUNNING:
		/* EVENT
		 * @description
		 * The pack_auth module is not running, so the battery packs cannot be authenticated.
		 */
		reporter.armingCheckFailure(NavModes::All, health_component_t::battery,
					    events::ID("check_pack_auth_not_running"),
					    events::Log::Error, "Pack auth: not running");
		break;

	case PKA_R_STALLED:
		/* EVENT
		 * @description
		 * The pack_auth module stopped publishing.
		 */
		reporter.armingCheckFailure(NavModes::All, health_component_t::battery,
					    events::ID("check_pack_auth_stalled"),
					    events::Log::Error, "Pack auth: task stalled");
		break;

	case PKA_R_BAD_ADDR_CONFIG:
		/* EVENT
		 * @description
		 * <param>PKA_ADDR</param> + <param>PKA_NUM</param> - 1 is outside the valid I2C address range.
		 */
		reporter.armingCheckFailure(NavModes::All, health_component_t::battery,
					    events::ID("check_pack_auth_bad_addr"),
					    events::Log::Error, "Pack auth: bad pack address config");
		break;

	case PKA_R_COUNT_NOT_SIGNED:
		/* EVENT
		 * @description
		 * <param>PKA_NUM</param> has no valid signature for this autopilot (<param>PKA_S0</param>..<param>PKA_S3</param>).
		 */
		reporter.armingCheckFailure(NavModes::All, health_component_t::battery,
					    events::ID("check_pack_auth_count_not_signed"),
					    events::Log::Error, "Pack auth: pack count not signed");
		break;

	case PKA_R_NOT_FOUND:
		/* EVENT
		 * @description
		 * Nothing answers at the I2C address of this pack slot.
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_not_found"),
						     events::Log::Error, "Pack {1}: pack not found", r.pack);
		break;

	case PKA_R_NO_ANSWER:
		/* EVENT
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_no_answer"),
						     events::Log::Error, "Pack {1}: no answer on I2C", r.pack);
		break;

	case PKA_R_NONCE_WRITE:
		/* EVENT
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_nonce_write"),
						     events::Log::Error, "Pack {1}: nonce write failed", r.pack);
		break;

	case PKA_R_NOT_RESPONDING:
		/* EVENT
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_not_responding"),
						     events::Log::Error, "Pack {1}: pack not responding", r.pack);
		break;

	case PKA_R_WRONG_RESPONSE:
		/* EVENT
		 * @description
		 * Wrong key, tampered or counterfeit pack.
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_wrong_response"),
						     events::Log::Error, "Pack {1}: wrong response", r.pack);
		break;

	case PKA_R_NOT_PROVISIONED:
		/* EVENT
		 * @description
		 * A genuine pack, but it has no serial, set or maximum use count yet.
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_not_provisioned"),
						     events::Log::Error, "Pack {1}: pack not provisioned", r.pack);
		break;

	case PKA_R_LIFE_USED_UP:
		/* EVENT
		 * @description
		 * The pack reached its maximum number of uses.
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_life_used_up"),
						     events::Log::Error, "Pack {1}: life used up", r.pack);
		break;

	case PKA_R_OTHER_SET:
		/* EVENT
		 * @description
		 * Every required pack must carry the same set id as pack 1.
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_other_set"),
						     events::Log::Error, "Pack {1}: other set", r.pack);
		break;

	case PKA_R_STALE:
	case PKA_R_STOPPED_ANSWERING:
		/* EVENT
		 */
		reporter.armingCheckFailure<uint8_t>(NavModes::All, health_component_t::battery,
						     events::ID("check_pack_auth_stale"),
						     events::Log::Error, "Pack {1}: proof is stale", r.pack);
		break;

	default:
		/* EVENT
		 */
		reporter.armingCheckFailure(NavModes::All, health_component_t::battery,
					    events::ID("check_pack_auth_starting"),
					    events::Log::Error, "Pack auth: starting");
		break;
	}

	if (reporter.mavlink_log_pub()) {
		if (r.pack) {
			mavlink_log_critical(reporter.mavlink_log_pub(), "Preflight Fail: Pack %u: %s\t",
					     (unsigned)r.pack, pack_auth_reason_str(r.reason));

		} else {
			mavlink_log_critical(reporter.mavlink_log_pub(), "Preflight Fail: Pack auth: %s\t",
					     pack_auth_reason_str(r.reason));
		}
	}
}
