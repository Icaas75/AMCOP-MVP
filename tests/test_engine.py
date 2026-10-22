"""Unit tests for AMCOP engine pure logic (no Docker/Mongo/SSH required).

Run:  python -m unittest discover -s tests -v
  or: python -m pytest tests -q
"""
import unittest

import amcop_engine


PS_HEADER = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"


def ps_line(user="root", pid="1234", command="/usr/sbin/sshd -D"):
    """Build a synthetic ps aux line whose COMMAND field starts at column 11."""
    # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND = 11 fields
    return f"{user} {pid}  0.0  0.1  1000  500 ?        Ss   10:00   0:00 {command}"


class TestAnalyzeProcessTree(unittest.TestCase):
    def test_clean_baseline_is_missed(self):
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="root", pid="1", command="/sbin/init"),
            ps_line(user="www", pid="220", command="/usr/sbin/nginx -g daemon off;"),
        ])
        status, score, indicators, audited = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "MISSED")
        self.assertEqual(score, 0)
        self.assertEqual(indicators, [])
        self.assertEqual(audited, 2)

    def test_admin_recon_detected(self):
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="root", pid="501", command="cat /etc/passwd"),
        ])
        status, score, indicators, audited = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "DETECTED")
        self.assertEqual(score, 40)  # Rule A weight == threshold
        self.assertEqual(len(indicators), 1)
        self.assertIn("501", indicators[0])

    def test_netstat_recon_detected(self):
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="root", pid="502", command="netstat -an"),
        ])
        status, score, *_ = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "DETECTED")

    def test_non_tty_ssh_session_detected(self):
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="root", pid="777", command="sshd: root@notty"),
        ])
        status, score, *_ = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "DETECTED")
        self.assertEqual(score, 40)

    def test_evasion_below_threshold_is_missed(self):
        # Rule B alone (30) is below the 40 threshold: intentional design.
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="www", pid="900", command="/bin/sh -c sleep 600"),
        ])
        status, score, *_ = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "MISSED")
        self.assertEqual(score, 30)

    def test_score_capped_at_100(self):
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="root", pid="1", command="cat /etc/shadow"),
            ps_line(user="root", pid="2", command="netstat -an"),
            ps_line(user="root", pid="3", command="ss -tulpn"),
            ps_line(user="root", pid="4", command="nohup sleep 9999"),
            ps_line(user="root", pid="5", command="sshd: root@notty"),
        ])
        status, score, indicators, audited = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "DETECTED")
        self.assertEqual(score, 100)  # 40+40+40+30+35 = 185 -> capped
        self.assertEqual(audited, 5)

    def test_malformed_lines_skipped(self):
        telemetry = "\n".join([
            PS_HEADER,
            "root 1 0.0",  # too few fields: ignored, no crash
            "",
        ])
        status, score, indicators, audited = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "MISSED")
        self.assertEqual(score, 0)
        self.assertEqual(audited, 1)  # header + 1 malformed line; empty line dropped by splitlines

    def test_non_root_recon_not_scored_by_rule_a(self):
        # Rule A requires the root user; a low-priv user running the same
        # command string should not trigger the admin-recon rule.
        telemetry = "\n".join([
            PS_HEADER,
            ps_line(user="www", pid="300", command="cat /etc/passwd"),
        ])
        status, score, *_ = amcop_engine.analyze_process_tree(telemetry)
        self.assertEqual(status, "MISSED")
        self.assertEqual(score, 0)


class TestEvaluateResilience(unittest.TestCase):
    def test_success_and_detected_is_resilient(self):
        self.assertEqual(amcop_engine.evaluate_resilience("SUCCESS", "DETECTED"), "RESILIENT")

    def test_success_but_missed_is_vulnerable(self):
        self.assertEqual(amcop_engine.evaluate_resilience("SUCCESS", "MISSED"), "VULNERABLE")

    def test_connection_error_is_vulnerable(self):
        self.assertEqual(
            amcop_engine.evaluate_resilience("CONNECTION_ERROR", "DETECTED"), "VULNERABLE")

    def test_telemetry_error_is_vulnerable(self):
        self.assertEqual(
            amcop_engine.evaluate_resilience("SUCCESS", "TELEMETRY_ERROR"), "VULNERABLE")


class TestTechniquePayloads(unittest.TestCase):
    def test_known_techniques(self):
        self.assertEqual(amcop_engine.get_payload_for_technique("T1087"), "cat /etc/passwd")
        self.assertEqual(
            amcop_engine.get_payload_for_technique("T1049"), "netstat -an || ss -tulpn")

    def test_unknown_technique_falls_back(self):
        self.assertEqual(amcop_engine.get_payload_for_technique("T9999"), "uname -a")


if __name__ == "__main__":
    unittest.main()
