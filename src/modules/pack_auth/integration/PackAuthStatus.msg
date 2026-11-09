# Battery pack authentication status
#
# Published by the pack_auth module (10 Hz) and read by the arming gate in Commander.
# A missing or stale (older than 2 s) message means the gate is closed.
# gate_reason / pack_reason use the PackAuthReason numbers of src/modules/pack_auth/pack_auth_reasons.h

uint64 timestamp				# time since system start (microseconds)

uint8 MAX_PACKS = 5

bool gate_open					# every required pack has a fresh, valid proof and the pack count is signed
uint8 gate_reason				# why the gate is closed (PackAuthReason), 0 when open
uint8 gate_pack					# 1-based slot the gate_reason is about, 0 = whole system
uint8 num_required				# PKA_NUM as accepted by the module
bool detecting					# pack count not signed for this autopilot: the module only reports what it finds

bool[5] pack_ok					# slot N has a valid, in-date proof
uint8[5] pack_reason			# PackAuthReason per slot
uint16[5] serial				# authenticated record of each pack (valid when pack_ok)
uint32[5] set_id
uint32[5] activated				# YYYYMMDD
uint16[5] use_count
uint16[5] max_count
