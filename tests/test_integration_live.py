"""Live integration test: full Red -> Blue -> White cycle against the lab.

Requires Docker + the target container running. Skips automatically when infra
is unavailable so the hermetic suite always passes offline.

Run:  python -m unittest discover -s tests -v
"""
import unittest

import amcop_engine
import config


def _infra_available():
    try:
        import docker
        client = docker.from_env()
        client.containers.get(config.TARGET_CONTAINER).reload()
        return True
    except Exception:
        return False


INFRA = _infra_available()


@unittest.skipUnless(INFRA, "lab infra (Docker target container) not available")
class TestLiveOrchestrationCycle(unittest.TestCase):
    def test_full_cycle_produces_consistent_report(self):
        report = amcop_engine.trigger_manual_simulation("T1087")

        # Every field the dashboard consumes must exist and be typed correctly.
        self.assertIn(report["red_outcome"], ("SUCCESS", "FAILED", "CONNECTION_ERROR"))
        self.assertIn(report["blue_outcome"], ("DETECTED", "MISSED", "TELEMETRY_ERROR"))
        self.assertIn(report["system_resilience"], ("RESILIENT", "VULNERABLE"))
        self.assertTrue(report["red_raw_console"])
        self.assertTrue(report["blue_raw_console"])

        # Verdict must agree with the pure rule.
        expected = amcop_engine.evaluate_resilience(
            report["red_outcome"], report["blue_outcome"])
        self.assertEqual(report["system_resilience"], expected)

        # The record must actually be persisted to MongoDB.
        client = config.get_mongo_client()
        stored = client[config.MONGO_DB][config.MONGO_COLLECTION].find_one(
            {"timestamp": report["timestamp"]}, sort=[("_id", -1)])
        self.assertIsNotNone(stored, "cycle report not found in MongoDB")
        self.assertEqual(stored["system_resilience"], report["system_resilience"])
        self.assertEqual(stored["red_outcome"], report["red_outcome"])
        self.assertEqual(stored["blue_outcome"], report["blue_outcome"])


@unittest.skipUnless(INFRA, "lab infra (Docker target container) not available")
class TestAllTechniquesEndToEnd(unittest.TestCase):
    """Full Red -> Blue -> White cycle for every implemented technique,
    including the newly added T1082 and T1016."""

    def test_every_registered_technique_produces_full_report(self):
        for tech_id in sorted(amcop_engine.TECHNIQUES):
            with self.subTest(technique=tech_id):
                report = amcop_engine.trigger_manual_simulation(tech_id)

                self.assertEqual(report["red_outcome"], "SUCCESS", f"{tech_id} red failed")
                self.assertEqual(report["blue_outcome"], "DETECTED", f"{tech_id} blue missed")
                self.assertEqual(report["system_resilience"], "RESILIENT")
                self.assertEqual(report["technique_name"],
                                 amcop_engine.TECHNIQUES[tech_id]["name"])

                # Evaluation-integrity fields required by the acceptance brief.
                self.assertEqual(report["confusion_class"], "TP")
                self.assertIsInstance(report["detection_latency_ms"], int)
                self.assertGreater(report["detection_latency_ms"], 0)
                evidence = report["detection_evidence"]
                self.assertIsNotNone(evidence)
                self.assertGreaterEqual(evidence["anomaly_score"],
                                        evidence["threshold"])
                self.assertTrue(evidence["risk_indicators"])
                self.assertTrue(report["detection_rationale"])

                # The executed payload must be the technique's own command.
                payload = amcop_engine.TECHNIQUES[tech_id]["payload"].split(" || ")[0]
                self.assertIn(payload.split()[0], report["red_raw_console"])

                # Persisted with the new fields.
                client = config.get_mongo_client()
                stored = client[config.MONGO_DB][config.MONGO_COLLECTION].find_one(
                    {"timestamp": report["timestamp"]}, sort=[("_id", -1)])
                self.assertIsNotNone(stored)
                self.assertEqual(stored["confusion_class"], "TP")
                self.assertEqual(stored["detection_latency_ms"],
                                 report["detection_latency_ms"])


@unittest.skipUnless(INFRA, "lab infra (Docker target container) not available")
class TestDetectionRepeatability(unittest.TestCase):
    def test_detection_is_repeatable_across_cycles(self):
        """The observation-window fix must yield DETECTED on every live cycle."""
        results = []
        for _ in range(3):
            report = amcop_engine.trigger_manual_simulation("T1087")
            results.append((report["red_outcome"], report["blue_outcome"]))

        for red, blue in results:
            self.assertEqual(red, "SUCCESS", f"red failed: {results}")
            self.assertEqual(blue, "DETECTED", f"blue not repeatable: {results}")


if __name__ == "__main__":
    unittest.main()
