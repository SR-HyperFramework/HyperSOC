import unittest
from datetime import datetime, timedelta, timezone

from worker_replay import decile_medians, service_times

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


class ServiceTimeTests(unittest.TestCase):
    def test_backlog_jobs_are_measured_from_previous_completion(self):
        # All three are enqueued at t=0; one worker finishes them at 2, 5 and 6.
        jobs = [(at(0), at(5)), (at(0), at(2)), (at(0), at(6))]
        self.assertEqual(service_times(jobs), [2.0, 3.0, 1.0])

    def test_idle_worker_measures_from_enqueue(self):
        # The second job arrives after the worker went idle.
        jobs = [(at(0), at(1)), (at(10), at(12))]
        self.assertEqual(service_times(jobs), [1.0, 2.0])

    def test_decile_medians_cover_ten_buckets(self):
        self.assertEqual(decile_medians([float(value) for value in range(20)]), [0.5, 2.5, 4.5, 6.5, 8.5, 10.5, 12.5, 14.5, 16.5, 18.5])
        self.assertEqual(decile_medians([3.0, 1.0]), [2.0])
        self.assertEqual(decile_medians([]), [])


if __name__ == "__main__":
    unittest.main()
