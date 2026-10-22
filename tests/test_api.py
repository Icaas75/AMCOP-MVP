"""API tests for the AMCOP FastAPI app (hermetic: engine and DB mocked).

Live infra is NOT required. Run:  python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as app_module
import amcop_engine
import config


class TestHealthEndpoint(unittest.TestCase):
    def test_health_reports_status(self):
        client = TestClient(app_module.app)
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body["status"], ("OK",))
        self.assertIn(body["database"], ("UP", "DOWN"))


class TestDashboard(unittest.TestCase):
    def test_dashboard_serves_200_with_war_room_marker(self):
        client = TestClient(app_module.app)
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("AMCOP", resp.text)
        self.assertIn("EventSource", resp.text)  # SSE client present

    def test_dashboard_offers_every_registered_technique(self):
        # Regression: the selector hardcoded only T1087/T1049 while the
        # registry held four techniques.
        client = TestClient(app_module.app)
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        for tech in amcop_engine.TECHNIQUES:
            self.assertIn(f'value="{tech}"', resp.text,
                          f"{tech} missing from dashboard selector")
        # No phantom options for unregistered IDs.
        self.assertEqual(resp.text.count("<option "),
                         len(amcop_engine.TECHNIQUES))


class TestExecuteSimulation(unittest.TestCase):
    def test_successful_cycle_returns_result_summary(self):
        fake_report = {
            "red_outcome": "SUCCESS",
            "blue_outcome": "DETECTED",
            "system_resilience": "RESILIENT",
        }
        client = TestClient(app_module.app)
        with mock.patch.object(amcop_engine, "trigger_manual_simulation",
                               return_value=fake_report) as mocked:
            resp = client.post("/execute-simulation/T1087")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "LAUNCHED")
        self.assertEqual(body["technique"], "T1087")
        self.assertEqual(body["result"]["red_outcome"], "SUCCESS")
        self.assertEqual(body["result"]["blue_outcome"], "DETECTED")
        self.assertEqual(body["result"]["system_resilience"], "RESILIENT")
        mocked.assert_called_once_with("T1087")

    def test_all_registered_techniques_accepted(self):
        fake_report = {"red_outcome": "SUCCESS", "blue_outcome": "DETECTED",
                       "system_resilience": "RESILIENT"}
        client = TestClient(app_module.app)
        for tech in sorted(amcop_engine.TECHNIQUES):
            with mock.patch.object(amcop_engine, "trigger_manual_simulation",
                                   return_value=fake_report) as mocked:
                resp = client.post(f"/execute-simulation/{tech}")
            self.assertEqual(resp.status_code, 200, tech)
            self.assertEqual(resp.json()["technique"], tech)
            mocked.assert_called_once_with(tech)

    def test_unknown_technique_id_rejected_at_boundary(self):
        # Regression: NOT-A-TECHNIQUE previously returned 200 and wrote a
        # record with the uname fallback, inflating technique coverage.
        client = TestClient(app_module.app)
        with mock.patch.object(amcop_engine, "trigger_manual_simulation") as mocked:
            resp = client.post("/execute-simulation/NOT-A-TECHNIQUE")
        self.assertEqual(resp.status_code, 422)
        body = resp.json()
        self.assertEqual(body["status"], "ERROR")
        self.assertIn("T1087", body["registered"])  # registry echoed
        mocked.assert_not_called()  # engine never invoked

    def test_injection_style_id_rejected(self):
        # Slash-containing IDs never match the route (404, handler not
        # reached); slash-free garbage hits the handler and is rejected (422).
        # Either way the engine must not be invoked.
        client = TestClient(app_module.app)
        with mock.patch.object(amcop_engine, "trigger_manual_simulation") as mocked:
            resp = client.post("/execute-simulation/T1;cat /etc/shadow")
        self.assertIn(resp.status_code, (404, 422))
        mocked.assert_not_called()

        with mock.patch.object(amcop_engine, "trigger_manual_simulation") as mocked:
            resp = client.post("/execute-simulation/T1;id%3Brm")
        self.assertEqual(resp.status_code, 422)  # reaches handler, rejected
        mocked.assert_not_called()

    def test_engine_exception_returns_clean_500(self):
        client = TestClient(app_module.app)
        with mock.patch.object(amcop_engine, "trigger_manual_simulation",
                               side_effect=RuntimeError("boom")):
            resp = client.post("/execute-simulation/T1087")
        self.assertEqual(resp.status_code, 500)
        body = resp.json()
        self.assertEqual(body["status"], "ERROR")
        self.assertNotIn("boom", body["detail"])  # no internals leaked


class TestMetricsAggregation(unittest.TestCase):
    def test_metrics_computed_from_logs(self):
        fake_logs = [
            {"_id": "a", "system_resilience": "RESILIENT"},
            {"_id": "b", "system_resilience": "VULNERABLE"},
            {"_id": "c", "system_resilience": "RESILIENT"},
        ]

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            data = app_module.fetch_operational_history_sync()

        self.assertEqual(data["metrics"]["total"], 3)
        self.assertEqual(data["metrics"]["resilient"], 2)
        self.assertEqual(data["metrics"]["vulnerable"], 1)
        self.assertEqual(data["metrics"]["catch_rate"], 67)
        self.assertEqual(len(data["logs"]), 3)

    def test_confusion_matrix_and_detection_rate(self):
        fake_logs = [
            {"red_outcome": "SUCCESS", "blue_outcome": "DETECTED"},   # TP
            {"red_outcome": "SUCCESS", "blue_outcome": "MISSED"},     # FN
            {"red_outcome": "SUCCESS", "blue_outcome": "DETECTED"},   # TP
            {"red_outcome": "CONNECTION_ERROR", "blue_outcome": "MISSED"},  # TN
            {"red_outcome": "FAILED", "blue_outcome": "DETECTED"},    # FP
            {"system_resilience": "RESILIENT"},                        # legacy: excluded
        ]

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            data = app_module.fetch_operational_history_sync()

        confusion = data["metrics"]["confusion"]
        self.assertEqual(confusion["TP"], 2)
        self.assertEqual(confusion["FN"], 1)
        self.assertEqual(confusion["FP_SUSPECTED"], 1)
        self.assertEqual(confusion["TN"], 1)
        # detection_rate denominator = ground-truth-positive (TP+FN) = 3
        self.assertEqual(data["metrics"]["detection_rate"], 67)

    def test_telemetry_error_record_does_not_crash_metrics(self):
        # Regression: a real DB record with blue_outcome=TELEMETRY_ERROR
        # classifies as UNSCORED_TELEMETRY_ERROR and must not KeyError.
        fake_logs = [
            {"red_outcome": "SUCCESS", "blue_outcome": "TELEMETRY_ERROR"},
            {"red_outcome": "SUCCESS", "blue_outcome": "DETECTED"},
        ]

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            data = app_module.fetch_operational_history_sync()
        self.assertEqual(
            data["metrics"]["confusion"]["UNSCORED_TELEMETRY_ERROR"], 1)
        self.assertEqual(data["metrics"]["confusion"]["TP"], 1)

    def test_detection_rate_none_without_positive_cycles(self):
        fake_logs = [{"red_outcome": "CONNECTION_ERROR", "blue_outcome": "MISSED"}]

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            data = app_module.fetch_operational_history_sync()
        self.assertIsNone(data["metrics"]["detection_rate"])

    def test_metrics_zero_when_db_unreachable(self):
        with mock.patch.object(config, "get_mongo_client",
                               side_effect=RuntimeError("no db")):
            data = app_module.fetch_operational_history_sync()
        self.assertEqual(data["logs"], [])
        self.assertEqual(data["metrics"]["catch_rate"], 0)


class TestCORSRestricted(unittest.TestCase):
    def test_no_wildcard_cors_by_default(self):
        # Default config installs no CORS middleware; ensure no * origin.
        origins = []
        for middleware in app_module.app.user_middleware:
            origins.append(getattr(middleware, "kwargs", {}).get("allow_origins"))
        self.assertNotIn(["*"], origins)


class TestAssessmentReport(unittest.TestCase):
    def _fake_logs(self):
        return [
            {"mitre_technique": "T1087", "technique_name": "Account Discovery",
             "red_outcome": "SUCCESS", "blue_outcome": "DETECTED"},
            {"mitre_technique": "T1087", "technique_name": "Account Discovery",
             "red_outcome": "SUCCESS", "blue_outcome": "MISSED"},
            {"mitre_technique": "T1049", "technique_name": "Network Connections Discovery",
             "red_outcome": "CONNECTION_ERROR", "blue_outcome": "MISSED"},
        ]

    def test_report_structure_and_gap_detection(self):
        fake_logs = self._fake_logs()

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        client = TestClient(app_module.app)
        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            resp = client.get("/assessment-report")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()

        self.assertEqual(body["generated_from_cycles"], 3)
        t1087 = body["per_technique"]["T1087"]
        self.assertEqual(t1087["attempted"], 2)
        self.assertEqual(t1087["executed"], 2)
        self.assertEqual(t1087["detected"], 1)
        self.assertEqual(t1087["missed"], 1)
        t1049 = body["per_technique"]["T1049"]
        self.assertEqual(t1049["execution_failures"], 1)

        # Gaps derived strictly from the records: missed detection + execution
        # failure + never-attempted techniques (T1082/T1016).
        gaps_text = " ".join(body["gaps"])
        self.assertIn("T1087", gaps_text)
        self.assertIn("not detected", gaps_text)
        self.assertIn("T1049", gaps_text)
        self.assertIn("T1082", gaps_text)
        self.assertIn("T1016", gaps_text)
        self.assertTrue(body["limitations"])

    def test_headline_metrics_use_shared_sse_window(self):
        # Regression: report previously computed metrics over up to 500
        # records while the dashboard gauge used HISTORY_WINDOW (50), so the
        # two could disagree (100% vs 90%). Headline metrics must now be
        # computed over the same most-recent-HISTORY_WINDOW slice.
        # 60 records: 60 RESILIENT would tie; use 55 resilient + 5 vulnerable
        # so windowed (last 50 => all resilient => 100%) differs from full
        # 60 (92%).
        recent_50 = [{"mitre_technique": "T1087", "red_outcome": "SUCCESS",
                      "blue_outcome": "DETECTED",
                      "system_resilience": "RESILIENT"} for _ in range(55)]
        older_5 = [{"mitre_technique": "T1087", "red_outcome": "SUCCESS",
                    "blue_outcome": "MISSED",
                    "system_resilience": "VULNERABLE"} for _ in range(5)]
        # find().sort desc => list order newest-first
        fake_logs = recent_50 + older_5

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs[:n]  # honor the window, like Mongo does

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        client = TestClient(app_module.app)
        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            report = client.get("/assessment-report").json()
            sse_data = app_module.fetch_operational_history_sync()

        # Same definition, same window => identical headline numbers.
        self.assertEqual(report["metrics"]["catch_rate"],
                         sse_data["metrics"]["catch_rate"])
        self.assertEqual(report["metrics"]["detection_rate"],
                         sse_data["metrics"]["detection_rate"])
        self.assertEqual(report["metrics"]["confusion"],
                         sse_data["metrics"]["confusion"])
        # Window actually applied: newest 50 are all resilient => 100% here,
        # whereas the full 60-record history would be 92%.
        self.assertEqual(report["metrics"]["catch_rate"], 100)
        self.assertEqual(report["metrics"]["window"], app_module.HISTORY_WINDOW)
        # Per-technique still scans the wider history (60 records).
        self.assertEqual(report["generated_from_cycles"], 60)

    def test_unrecognized_records_excluded_from_coverage(self):
        # Regression: NOT-A-TECHNIQUE previously appeared as a first-class
        # per_technique row (inflating coverage) and left no gap note.
        fake_logs = [
            {"mitre_technique": "NOT-A-TECHNIQUE", "red_outcome": "SUCCESS",
             "blue_outcome": "DETECTED", "system_resilience": "RESILIENT"},
            {"mitre_technique": "T1087", "technique_name": "Account Discovery",
             "red_outcome": "SUCCESS", "blue_outcome": "DETECTED"},
        ]

        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return fake_logs

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        client = TestClient(app_module.app)
        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            body = client.get("/assessment-report").json()

        self.assertNotIn("NOT-A-TECHNIQUE", body["per_technique"])
        self.assertEqual(body["unrecognized_records"], 1)
        self.assertEqual(body["per_technique"]["T1087"]["attempted"], 1)
        self.assertTrue(any("unregistered" in g for g in body["gaps"]))

    def test_report_with_empty_db(self):
        class FakeCursor:
            def sort(self, *a, **k):
                return self

            def limit(self, n):
                return []

        class FakeCollection:
            def find(self):
                return FakeCursor()

        class FakeDB:
            def __getitem__(self, name):
                return FakeCollection()

        class FakeClient:
            def __getitem__(self, name):
                return FakeDB()

        client = TestClient(app_module.app)
        with mock.patch.object(config, "get_mongo_client", return_value=FakeClient()):
            resp = client.get("/assessment-report")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["generated_from_cycles"], 0)
        self.assertEqual(body["per_technique"], {})
        self.assertIn("T1082", " ".join(body["gaps"]))  # never attempted


if __name__ == "__main__":
    unittest.main()
