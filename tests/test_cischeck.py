import subprocess, sys, tempfile, unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cischeck import collector, safety
from cischeck.backends import MockBackend
from cischeck.catalog import CHECKS, Check
from cischeck.evaluator import evaluate, evaluate_all, summarize


def chk(op, expected, kind="registry", missing="FAIL"):
    return Check("T-1", "t", "s", "x", "High", kind, ("P", "N"), op, expected, missing, "fix")


class EvaluatorTests(unittest.TestCase):
    def snap(self, v):
        return {"registry": {"P|N": v}}

    def test_ops(self):
        self.assertEqual(evaluate(chk("eq", 1), self.snap(1))["status"], "PASS")
        self.assertEqual(evaluate(chk("eq", 1), self.snap(0))["status"], "FAIL")
        self.assertEqual(evaluate(chk("ge", 14), self.snap("14"))["status"], "PASS")   # numeric string
        self.assertEqual(evaluate(chk("between", [1, 5]), self.snap(0))["status"], "FAIL")
        self.assertEqual(evaluate(chk("in", [1, 2]), self.snap(2))["status"], "PASS")

    def test_missing_uses_default_policy(self):
        self.assertEqual(evaluate(chk("eq", 1, missing="PASS"), {"registry": {"P|N": None}})["status"], "PASS")
        self.assertEqual(evaluate(chk("eq", 1, missing="REVIEW"), {"registry": {}})["status"], "REVIEW")

    def test_collection_error_is_error_not_pass(self):
        self.assertEqual(evaluate(chk("eq", 1), {"registry": {"__error__": "denied"}})["status"], "ERROR")

    def test_non_numeric_goes_to_review(self):
        self.assertEqual(evaluate(chk("ge", 14), self.snap("Nunca"))["status"], "REVIEW")

    def test_bool_is_not_a_number(self):
        self.assertEqual(evaluate(chk("ge", 1), self.snap(True))["status"], "REVIEW")

    def test_audit_includes(self):
        c = Check("A", "a", "s", "x", "Low", "audit", ("Logon",), "includes", ["Success", "Failure"], "REVIEW", "f")
        self.assertEqual(evaluate(c, {"audit": {"Logon": "Success"}})["status"], "FAIL")
        self.assertEqual(evaluate(c, {"audit": {"Logon": "Success and Failure"}})["status"], "PASS")

    def test_service_absent_is_compliant(self):
        c = Check("S", "s", "s", "x", "Low", "service", ("Telnet",), "in", ["Disabled", "Absent"], "PASS", "f")
        self.assertEqual(evaluate(c, {"services": {"Telnet": None}})["status"], "PASS")
        self.assertEqual(evaluate(c, {"services": {"Telnet": {"Start": "Automatic"}}})["status"], "FAIL")

    def test_summary(self):
        s = summarize([{"status": "PASS", "section": "a", "severity": "Low"},
                       {"status": "FAIL", "section": "a", "severity": "High"}])
        self.assertEqual((s["pass"], s["fail"], s["compliance_pct"], s["high_severity_failures"]), (1, 1, 50.0, 1))


class CollectorTests(unittest.TestCase):
    def test_net_accounts_parsing(self):
        p = collector.parse_net_accounts("a?:  Never\nb:  1\nc:  42\nd:  8\ne:  None\nf:  Never\ng:  30\nh:  30\ni:  WORKSTATION")
        self.assertEqual((p["min_len"], p["history"], p["lockout_threshold"], p["max_age"]), (8, 0, 0, 42))

    def test_every_script_is_read_only(self):
        for script in collector.build_sections().values():
            safety.assert_read_only(script)

    def test_full_demo_pipeline(self):
        snap = collector.collect(MockBackend(), safety.KillSwitch(stop_files=()), log=lambda *_: None)
        results = evaluate_all(snap)
        self.assertEqual(len(results), len(CHECKS))
        self.assertEqual(summarize(results)["error"], 0)


class SafetyTests(unittest.TestCase):
    def test_guard_blocks_mutations(self):
        for bad in ["Set-ItemProperty a b", "Remove-Item x", "net user x y /add", "reg add HKLM\\x",
                    "echo hi > f.txt", "net accounts /minpwlen:3", "Invoke-Expression 1", "Start-Service x"]:
            with self.assertRaises(safety.SafetyError, msg=bad):
                safety.assert_read_only(bad)

    def test_scope(self):
        scope = safety.parse_scope(["192.168.56.0/24"])
        self.assertEqual(safety.check_target("192.168.56.10", scope), "192.168.56.10")
        with self.assertRaises(safety.SafetyError):
            safety.check_target("192.168.57.10", scope)

    def test_public_ip_refused_even_if_in_scope(self):
        with self.assertRaises(safety.SafetyError):
            safety.check_target("8.8.8.8", safety.parse_scope(["8.8.8.8"]))

    def test_scope_too_broad(self):
        with self.assertRaises(safety.SafetyError):
            safety.parse_scope(["10.0.0.0/16"])

    def test_time_window(self):
        safety.enforce_time_window("09:00-18:00", datetime(2026, 1, 1, 10, 0))
        with self.assertRaises(safety.SafetyError):
            safety.enforce_time_window("09:00-18:00", datetime(2026, 1, 1, 20, 0))
        safety.enforce_time_window("22:00-02:00", datetime(2026, 1, 1, 23, 30))   # overnight

    def test_confirmation_must_match_target(self):
        safety.confirm_authorization("10.0.0.5", ask=lambda _: "I AM AUTHORIZED TO AUDIT 10.0.0.5")
        for wrong in ("yes", "YES", "I AM AUTHORIZED TO AUDIT 10.0.0.6"):
            with self.assertRaises(safety.SafetyError):
                safety.confirm_authorization("10.0.0.5", ask=lambda _: wrong)

    def test_kill_switch_stop_file(self):
        with tempfile.TemporaryDirectory() as d:
            stop = Path(d) / "STOP"
            ks = safety.KillSwitch(stop_files=(stop,))
            ks.check()
            stop.touch()
            with self.assertRaises(safety.Aborted):
                ks.check()


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "cischeck", *args], capture_output=True, text=True,
                              cwd=Path(__file__).resolve().parent.parent)

    def test_default_is_dry_run(self):
        r = self.run_cli()
        self.assertEqual(r.returncode, 0)
        self.assertIn("DRY-RUN", r.stdout)

    def test_remote_target_without_scope_refused(self):
        r = self.run_cli("--target", "192.168.1.50")
        self.assertEqual(r.returncode, 3)
        self.assertIn("Scope is empty", r.stdout)

    def test_live_needs_username(self):
        self.assertEqual(self.run_cli("--live").returncode, 3)


if __name__ == "__main__":
    unittest.main()
