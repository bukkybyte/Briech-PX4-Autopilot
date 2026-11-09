#pragma once

#include <stdint.h>

// Why a pack (or the whole gate) is not open. Stored in the pack_auth_status uORB message
// (gate_reason / pack_reason[]), so the numbers must not change once packs are in the field.
enum PackAuthReason : uint8_t {
	PKA_R_OK                = 0,
	PKA_R_NOT_RUNNING       = 1,   // consumer side: pack_auth is not publishing
	PKA_R_STARTING          = 2,
	PKA_R_BAD_ADDR_CONFIG   = 3,
	PKA_R_COUNT_NOT_SIGNED  = 4,
	PKA_R_NOT_FOUND         = 5,
	PKA_R_NO_ANSWER         = 6,
	PKA_R_NONCE_WRITE       = 7,
	PKA_R_NOT_RESPONDING    = 8,
	PKA_R_WRONG_RESPONSE    = 9,
	PKA_R_NOT_PROVISIONED   = 10,
	PKA_R_LIFE_USED_UP      = 11,
	PKA_R_OTHER_SET         = 12,
	PKA_R_STALE             = 13,
	PKA_R_STOPPED_ANSWERING = 14,
	PKA_R_STALLED           = 15,  // consumer side: the status stopped updating
	PKA_R_COUNT             = 16
};

static inline const char *pack_auth_reason_str(uint8_t r)
{
	switch (r) {
	case PKA_R_OK:                return "authenticated";

	case PKA_R_NOT_RUNNING:       return "not running";

	case PKA_R_STARTING:          return "starting";

	case PKA_R_BAD_ADDR_CONFIG:   return "bad pack address config";

	case PKA_R_COUNT_NOT_SIGNED:  return "pack count not signed";

	case PKA_R_NOT_FOUND:         return "pack not found";

	case PKA_R_NO_ANSWER:         return "no answer on I2C";

	case PKA_R_NONCE_WRITE:       return "nonce write failed";

	case PKA_R_NOT_RESPONDING:    return "pack not responding";

	case PKA_R_WRONG_RESPONSE:    return "wrong response";

	case PKA_R_NOT_PROVISIONED:   return "pack not provisioned";

	case PKA_R_LIFE_USED_UP:      return "life used up";

	case PKA_R_OTHER_SET:         return "other set";

	case PKA_R_STALE:             return "proof is stale";

	case PKA_R_STOPPED_ANSWERING: return "pack stopped answering";

	case PKA_R_STALLED:           return "task stalled";

	default:                      return "unknown";
	}
}
