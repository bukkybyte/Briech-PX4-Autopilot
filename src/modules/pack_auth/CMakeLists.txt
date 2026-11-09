############################################################################
#
# pack_auth: battery pack authentication (SipHash-2-4 challenge/response over I2C).
# smartpack_key.h is NOT in git: create it with `bash setup.sh key` (see README).
#
############################################################################

# ModuleBase changed from the ModuleBase<T> template (v1.17 and older) to a Descriptor (newer main)
file(READ ${PX4_SOURCE_DIR}/platforms/common/include/px4_platform_common/module.h PACK_AUTH_MODULE_H)
string(FIND "${PACK_AUTH_MODULE_H}" "struct Descriptor" PACK_AUTH_DESC_POS)

px4_add_module(
	MODULE modules__pack_auth
	MAIN pack_auth
	SRCS
		pack_auth.cpp
		pack_auth_core.cpp
	MODULE_CONFIG
		module.yaml
	DEPENDS
		drivers__device
	)

if(NOT PACK_AUTH_DESC_POS EQUAL -1)
	target_compile_definitions(modules__pack_auth PRIVATE PACK_AUTH_MODULEBASE_DESC=1)
else()
	target_compile_definitions(modules__pack_auth PRIVATE PACK_AUTH_MODULEBASE_DESC=0)
endif()
