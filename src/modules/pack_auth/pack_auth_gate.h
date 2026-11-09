#pragma once

// Consumer side of the pack_auth_status message (Commander's arm() and the health check).
// Header-only and independent of the uORB headers, so the host tests can compile it as is.

#include <stdint.h>
#include "pack_auth_config.h"
#include "pack_auth_reasons.h"

struct PackAuthGateResult {
	bool    open;
	uint8_t reason;
	uint8_t pack;      // 1-based slot, 0 = whole system
};

/**
 * Fail-closed decision on a received pack_auth_status. S is pack_auth_status_s.
 * have: a message was ever published. now_us: hrt_absolute_time().
 */
template<typename S>
static inline PackAuthGateResult pack_auth_gate_evaluate(bool have, const S &s, uint64_t now_us)
{
	PackAuthGateResult r{false, PKA_R_NOT_RUNNING, 0};

	if (!have) {
		return r;
	}

	if (now_us < s.timestamp || (now_us - s.timestamp) > PKA_STATUS_MAX_AGE_US) {
		r.reason = PKA_R_STALLED;
		return r;
	}

	if (s.gate_open && s.num_required >= PACK_AUTH_NUM_MIN && s.num_required <= PACK_AUTH_MAX_PACKS) {
		r.open = true;
		r.reason = PKA_R_OK;
		return r;
	}

	r.reason = (s.gate_reason == PKA_R_OK) ? (uint8_t)PKA_R_STARTING : s.gate_reason;
	r.pack = s.gate_pack;
	return r;
}
