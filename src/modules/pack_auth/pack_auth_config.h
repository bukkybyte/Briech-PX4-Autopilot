#pragma once

#if defined(__has_include)
#  if __has_include(<px4_boardconfig.h>)
#    include <px4_boardconfig.h>   // CONFIG_PACK_AUTH_* from the board's .px4board
#  endif
#endif

// Build switches. On a PX4 build they come from the board's .px4board (Kconfig, see Kconfig in this
// folder); on the host (tests) they default to the values below or come from -D.

#ifndef PACK_AUTH_MAX_PACKS
#define PACK_AUTH_MAX_PACKS 5
#endif

// firmware floor: PKA_NUM can never be set below this
#ifndef PACK_AUTH_NUM_MIN
#  ifdef CONFIG_PACK_AUTH_NUM_MIN
#    define PACK_AUTH_NUM_MIN CONFIG_PACK_AUTH_NUM_MIN
#  else
#    define PACK_AUTH_NUM_MIN 1
#  endif
#endif

// 1 = the pack count must carry a valid signature for this autopilot (default, safe)
#ifndef PACK_AUTH_CFG_SIGNED
#  ifdef CONFIG_PACK_AUTH_UNSIGNED_COUNT
#    define PACK_AUTH_CFG_SIGNED 0
#  else
#    define PACK_AUTH_CFG_SIGNED 1
#  endif
#endif

// armed at least this long => one use is counted (0 = every arm)
#ifndef PACK_AUTH_MIN_FLIGHT_S
#  ifdef CONFIG_PACK_AUTH_MIN_FLIGHT_S
#    define PACK_AUTH_MIN_FLIGHT_S CONFIG_PACK_AUTH_MIN_FLIGHT_S
#  else
#    define PACK_AUTH_MIN_FLIGHT_S 30
#  endif
#endif

// timing, milliseconds
#define PKA_SCAN_MS      2000    // rescan period while a pack isn't found
#define PKA_RETRY_MS     1000    // gap between challenges to one pack
#define PKA_TIMEOUT_MS    400    // time a pack has to answer
#define PKA_REAUTH_MS    3000    // re-challenge each pack this often
#define PKA_FRESH_MS     8000    // arming needs a good answer at most this old
#define PKA_DETECT_MS   10000    // detection report period while unprovisioned
#define PKA_USE_TRIES       5    // attempts to get a flight counted by the pack
#define PKA_STATUS_MAX_AGE_US 2000000ULL   // consumer: the published status may be at most this old
