#!/usr/bin/env python3
"""Hook pack_auth into a PX4 tree (anchors validated on PX4 v1.17.0 and on main of Nov 2026).

  apply_patch.py <px4-dir> [--board vendor/model ...] [--unsigned] [--min-flight S] [--dry-run]

Edits, each only if not already done (it also recognises the same edits made by hand):
  msg/CMakeLists.txt                                    register the pack_auth_status message
  msg/PackAuthStatus.msg                                (copied from integration/)
  src/modules/commander/HealthAndArmingChecks/checks/packAuthCheck.cpp/.hpp   (copied)
  src/modules/commander/HealthAndArmingChecks/CMakeLists.txt, HealthAndArmingChecks.hpp
                                                        the pre-arm check and its messages
  src/modules/commander/Commander.hpp/.cpp              the arming gate inside Commander::arm()
  src/modules/logger/logged_topics.cpp                  log pack_auth_status
  boards/<vendor>/<model>/default.px4board              CONFIG_MODULES_PACK_AUTH=y (+ options)
  boards/<vendor>/<model>/init/rc.board_sensors         start the module at boot

If an anchor is not found exactly once the edit is NOT made; the snippet is printed so you can add it by
hand, and the exit code is 2.
"""
import argparse, os, re, shutil, sys

TAG = "[PX4_PackAuth]"
CFG = "#include <px4_platform_common/px4_config.h>   // CONFIG_MODULES_PACK_AUTH must be defined before the #if below\n"
HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
manual = []
changed = []


def rd(p):
    with open(p) as f:
        return f.read()


def wr(p, s, dry):
    if not dry:
        with open(p, "w") as f:
            f.write(s)


def edit_file(root, rel, edits, dry):
    """edits: list of (name, fn(s) -> new_s or None, present_regex). fn returns None when its anchor
    is not found exactly once. An edit counts as done if present_regex or its TAG is in the file."""
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        manual.append((rel, "file not found", ""))
        print("  MANUAL %-58s file not found" % rel)
        return
    s = rd(path)
    for name, fn, present, snippet in edits:
        if ("%s %s" % (TAG, name)) in s or re.search(present, s):
            print("  skip   %-58s %s (already done)" % (rel, name))
            continue
        ns = fn(s)
        if ns is None:
            print("  MANUAL %-58s %s (anchor not found exactly once)" % (rel, name))
            manual.append((rel, name, snippet))
            continue
        s = ns
        changed.append((rel, name))
        print("  edit   %-58s %s" % (rel, name))
    wr(path, s, dry)


def insert_before_once(pattern, text, flags=re.M):
    """returns fn(s): insert text before the single match of pattern"""
    def fn(s):
        m = list(re.finditer(pattern, s, flags))
        if len(m) != 1:
            return None
        return s[:m[0].start()] + text + s[m[0].start():]
    return fn


def insert_after_once(pattern, text, flags=re.M):
    def fn(s):
        m = list(re.finditer(pattern, s, flags))
        if len(m) != 1:
            return None
        return s[:m[0].end()] + text + s[m[0].end():]
    return fn


def copy_file(src, dst, dry):
    rel = os.path.relpath(dst, ROOT)
    if os.path.exists(dst) and rd(dst) == rd(src):
        print("  skip   %-58s (identical)" % rel)
        return
    if not dry:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
    changed.append((rel, "copied"))
    print("  copy   %-58s" % rel)


# ------------------------------------------------------------------------------------------------
GATE = '''#if CONFIG_MODULES_PACK_AUTH   // %(t)s arming gate: not skippable (forced arm, arm-on-boot, RC re-arm grace)
	{
		pack_auth_status_s pack_status{};
		const bool have_pack_status = _pack_auth_status_sub.copy(&pack_status);
		const PackAuthGateResult pack_gate = pack_auth_gate_evaluate(have_pack_status, pack_status, hrt_absolute_time());

		if (!pack_gate.open) {
			tune_negative(true);

			if (pack_gate.pack) {
				mavlink_log_critical(&_mavlink_log_pub, "Arming denied: Pack %%u: %%s\\t", (unsigned)pack_gate.pack,
						     pack_auth_reason_str(pack_gate.reason));

			} else {
				mavlink_log_critical(&_mavlink_log_pub, "Arming denied: Pack auth: %%s\\t", pack_auth_reason_str(pack_gate.reason));
			}

			events::send(events::ID("commander_arm_denied_pack_auth"), {events::Log::Critical, events::LogInternal::Info},
				     "Arming denied: battery pack authentication failed");
			return TRANSITION_DENIED;
		}
	}
#endif

''' % {"t": TAG}

ARM_ANCHOR = r"^[ \t]*// allow a grace period for re-arming[^\n]*\n"


def patch_msg(root, dry):
    edit_file(root, "msg/CMakeLists.txt", [(
        "message list",
        insert_before_once(r"^[ \t]*ParameterResetRequest\.msg[ \t]*\n", "\tPackAuthStatus.msg\n"),
        r"PackAuthStatus\.msg", "\tPackAuthStatus.msg   (in the msg_files list)")], dry)
    copy_file(os.path.join(KIT, "integration", "PackAuthStatus.msg"), os.path.join(root, "msg", "PackAuthStatus.msg"), dry)


def patch_checks(root, dry):
    d = os.path.join(root, "src/modules/commander/HealthAndArmingChecks")
    for f in ("packAuthCheck.cpp", "packAuthCheck.hpp"):
        copy_file(os.path.join(KIT, "integration", f), os.path.join(d, "checks", f), dry)

    cm = ("if(CONFIG_MODULES_PACK_AUTH)   # %s check source\n"
          "\ttarget_sources(health_and_arming_checks PRIVATE checks/packAuthCheck.cpp)\n"
          "endif()\n\n") % TAG

    def cmake_fn(s):
        m = list(re.finditer(r"^px4_add_library\(health_and_arming_checks\b[^)]*\)[ \t]*\n", s, re.M))
        if len(m) != 1:
            return None
        return s[:m[0].end()] + "\n" + cm + s[m[0].end():]

    edit_file(root, "src/modules/commander/HealthAndArmingChecks/CMakeLists.txt", [(
        "check source", cmake_fn, r"packAuthCheck\.cpp", cm)], dry)

    def inc_fn(s):
        inc = list(re.finditer(r'^#include "checks/[^"\n]+"[ \t]*\n', s, re.M))
        if not inc:
            return None
        e = inc[-1].end()
        return s[:e] + ('%s#if CONFIG_MODULES_PACK_AUTH   // %s include\n#include "checks/packAuthCheck.hpp"\n#endif\n' % (CFG, TAG)) + s[e:]

    def arr_fn(s):
        m = list(re.finditer(r"^([ \t]*)HealthAndArmingCheckBase \*_checks\[(\d+)\] = \{[^\n]*\n", s, re.M))
        if len(m) != 1:
            return None
        end = s.find("\n\t};", m[0].end())
        if end < 0:
            return None
        n = int(m[0].group(2)) + 1
        head = ("#if CONFIG_MODULES_PACK_AUTH   // %s member\n\tPackAuthChecks _pack_auth_checks;\n#endif\n\n" % TAG)
        line = m[0].group(0).replace("[%s]" % m[0].group(2), "[%d]" % n).rstrip("\n") + "   // %s list size\n" % TAG
        tail = ("\n#if CONFIG_MODULES_PACK_AUTH   // %s list entry\n\t\t&_pack_auth_checks,\n#endif" % TAG)
        return s[:m[0].start()] + head + line + s[m[0].end():end] + tail + s[end:]

    edit_file(root, "src/modules/commander/HealthAndArmingChecks/HealthAndArmingChecks.hpp", [
        ("include", inc_fn, r"packAuthCheck\.hpp", '#include "checks/packAuthCheck.hpp"   (under #if CONFIG_MODULES_PACK_AUTH)'),
        ("member and list", arr_fn, r"_pack_auth_checks",
         "PackAuthChecks _pack_auth_checks;   before the _checks array, and &_pack_auth_checks, at the end of it (array size + 1)"),
    ], dry)


def patch_commander(root, dry):
    edit_file(root, "src/modules/commander/Commander.hpp", [
        ("topic include",
         insert_after_once(r"^#include <uORB/topics/vtol_vehicle_status\.h>[ \t]*\n",
                           "%s#if CONFIG_MODULES_PACK_AUTH   // %s topic include\n#include <uORB/topics/pack_auth_status.h>\n#endif\n" % (CFG, TAG)),
         r"pack_auth_status\.h", "#include <uORB/topics/pack_auth_status.h>   (under #if CONFIG_MODULES_PACK_AUTH)"),
        ("subscription",
         insert_after_once(r"^[ \t]*uORB::Subscription[ \t]+_vtol_vehicle_status_sub\{[^\n]*\n",
                           "#if CONFIG_MODULES_PACK_AUTH   // %s subscription\n"
                           "\tuORB::Subscription\t\t\t\t\t_pack_auth_status_sub{ORB_ID(pack_auth_status)};\n#endif\n" % TAG),
         r"_pack_auth_status_sub", "uORB::Subscription _pack_auth_status_sub{ORB_ID(pack_auth_status)};   (in the private members)"),
    ], dry)
    edit_file(root, "src/modules/commander/Commander.cpp", [
        ("gate include",
         insert_after_once(r'^#include "Commander\.hpp"[ \t]*\n',
                           "%s#if CONFIG_MODULES_PACK_AUTH   // %s gate include\n#include <modules/pack_auth/pack_auth_gate.h>\n#endif\n" % (CFG, TAG)),
         r"pack_auth_gate\.h", "#include <modules/pack_auth/pack_auth_gate.h>   (under #if CONFIG_MODULES_PACK_AUTH)"),
        ("arm gate", insert_before_once(ARM_ANCHOR, GATE), r"pack_auth_gate_evaluate\(",
         "in Commander::arm(), after the 'calibrating' check and before the re-arming grace period:\n" + GATE),
    ], dry)


def patch_logger(root, dry):
    edit_file(root, "src/modules/logger/logged_topics.cpp", [(
        "log topic",
        insert_after_once(r'^[ \t]*add_topic\("onboard_computer_status"[^\n]*\n',
                          '\tadd_topic("pack_auth_status", 1000);   // %s log topic\n' % TAG),
        r"pack_auth_status", '\tadd_topic("pack_auth_status", 1000);')], dry)


def patch_board(root, boards, unsigned, min_flight, dry):
    for b in boards:
        rel = "boards/%s/default.px4board" % b
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            manual.append((rel, "board config", "add CONFIG_MODULES_PACK_AUTH=y to the board's default.px4board"))
            print("  MANUAL %-58s board config (file not found)" % rel)
            continue
        s = rd(path)
        if "CONFIG_MODULES_PACK_AUTH" in s:
            print("  skip   %-58s (already has CONFIG_MODULES_PACK_AUTH)" % rel)
        else:
            if not s.endswith("\n"):
                s += "\n"
            s += "CONFIG_MODULES_PACK_AUTH=y\n"
            if unsigned:
                s += "CONFIG_PACK_AUTH_UNSIGNED_COUNT=y\n"
            if min_flight is not None:
                s += "CONFIG_PACK_AUTH_MIN_FLIGHT_S=%d\n" % min_flight
            wr(path, s, dry)
            changed.append((rel, "config"))
            print("  edit   %-58s CONFIG_MODULES_PACK_AUTH=y%s" % (rel, " (unsigned count)" if unsigned else ""))

        rel = "boards/%s/init/rc.board_sensors" % b
        path = os.path.join(root, rel)
        start = "\n# battery pack authentication %s\npack_auth start\n" % TAG
        if os.path.exists(path):
            s = rd(path)
            if re.search(r"^\s*pack_auth\s+start", s, re.M):
                print("  skip   %-58s (already starts pack_auth)" % rel)
                continue
            if not s.endswith("\n"):
                s += "\n"
            wr(path, s + start, dry)
        else:
            if not dry:
                os.makedirs(os.path.dirname(path), exist_ok=True)
            wr(path, "#!/bin/sh\n#\n# board specific sensors init\n#\n" + start, dry)
        changed.append((rel, "start"))
        print("  edit   %-58s pack_auth start" % rel)


def main():
    global ROOT
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--board", action="append", default=None, help="vendor/model, default cubepilot/cubeorange")
    ap.add_argument("--unsigned", action="store_true", help="plain PKA_NUM, no signature needed (bench work)")
    ap.add_argument("--min-flight", type=int, default=None, help="armed seconds that count as a use (default 30)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    ROOT = os.path.abspath(a.root)
    for need in ("src/modules/commander/Commander.cpp", "src/modules/logger/logged_topics.cpp", "msg/CMakeLists.txt"):
        if not os.path.exists(os.path.join(ROOT, need)):
            sys.exit("%s is not a PX4 checkout (missing %s)" % (ROOT, need))
    if not os.path.exists(os.path.join(ROOT, "src/modules/pack_auth/pack_auth_core.cpp")):
        sys.exit("src/modules/pack_auth is missing in %s (put this folder there first)" % ROOT)
    print("dry run, nothing is written" if a.dry_run else "patching:")
    patch_msg(ROOT, a.dry_run)
    patch_checks(ROOT, a.dry_run)
    patch_commander(ROOT, a.dry_run)
    patch_logger(ROOT, a.dry_run)
    patch_board(ROOT, a.board or ["cubepilot/cubeorange"], a.unsigned, a.min_flight, a.dry_run)
    print("\n%d edit(s) %s." % (len(changed), "would be made" if a.dry_run else "made"))
    if manual:
        print("\nMANUAL EDITS NEEDED:")
        for rel, name, snippet in manual:
            print("\n--- %s : %s\n%s" % (rel, name, snippet))
        sys.exit(2)


if __name__ == "__main__":
    main()
