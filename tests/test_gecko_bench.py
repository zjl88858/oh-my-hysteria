# SPDX-License-Identifier: MIT-0

import unittest
from pathlib import Path
import tempfile
from unittest import mock

from tests.network.gecko_bench import DEFAULT_MODES, MODES, Network, client_run, log_records, transfer_summary, transfer_valid
from tests.network.summarize import mbps, summarize


class GeckoBenchmarkTests(unittest.TestCase):
    def test_path_change_is_applied_once_and_joined(self):
        timer = mock.Mock()
        def make_timer(delay, callback):
            self.assertEqual(delay, 2)
            timer.start.side_effect = callback
            return timer
        network = mock.Mock(names={"c": "test-c"})
        records = '{"msg":"download complete","bytes":4096}\n{"msg":"upload complete","bytes":4096}\n'
        completed = mock.Mock(returncode=0, stdout=records, stderr="")
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("tests.network.gecko_bench.threading.Timer", side_effect=make_timer):
                with mock.patch("tests.network.gecko_bench.subprocess.run", return_value=completed):
                    entry = client_run(network, Path("binary"), Path("private.json"), Path(directory), "step", 4096, (10, 240, 100, 0))
        self.assertTrue(entry["valid"])
        self.assertTrue(entry["path_change"]["applied"])
        network.shape.assert_called_once_with(10, 240, 100, 0)
        timer.cancel.assert_called_once()
        timer.join.assert_called_once()

    def test_path_change_failure_is_not_a_valid_transfer(self):
        timer = mock.Mock()
        def make_timer(delay, callback):
            timer.start.side_effect = callback
            return timer
        network = mock.Mock(names={"c": "test-c"})
        network.shape.side_effect = RuntimeError("test shaping error")
        completed = mock.Mock(returncode=0, stdout='{"msg":"download complete","bytes":4096}\n{"msg":"upload complete","bytes":4096}\n', stderr="")
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("tests.network.gecko_bench.threading.Timer", side_effect=make_timer):
                with mock.patch("tests.network.gecko_bench.subprocess.run", return_value=completed):
                    entry = client_run(network, Path("binary"), Path("private.json"), Path(directory), "step", 4096, (10, 240, 100, 0))
        self.assertFalse(entry["valid"])
        self.assertIn("shaping error", entry["path_change"]["error"])

    def test_modes_keep_bbr3_explicit_and_do_not_apply_hystart_to_bbr(self):
        self.assertEqual(len(MODES), 10)
        self.assertEqual(MODES["geodesic"], {"type": "geodesic"})
        self.assertNotIn("geodesic", DEFAULT_MODES)
        self.assertEqual(MODES["copa"], {"type": "copa"})
        self.assertNotIn("copa", DEFAULT_MODES)
        self.assertEqual(len(DEFAULT_MODES), 6)
        for profile in ("conservative", "aggressive"):
            self.assertEqual(MODES["bbr3-" + profile], {"type": "bbr3", "bbrProfile": profile})
            self.assertNotIn("bbr3-" + profile, DEFAULT_MODES)
        self.assertEqual(MODES["bbr"]["slowStart"], "legacy")
        self.assertEqual(MODES["bbr3"], {"type": "bbr3"})
        self.assertTrue(all(mode["type"] in ("bbr", "bbr3", "cubic", "reno", "copa", "geodesic") for mode in MODES.values()))

    def test_parse_json_mixed_with_non_json_stderr(self):
        text = 'warning\n{"msg":"download complete","bytes":4096}\nnot-json\n[]\nnull\n'
        self.assertEqual(log_records(text), [{"msg": "download complete", "bytes": 4096}])

    def test_summary_excludes_progress_and_completion_without_byte_count(self):
        text = '\n'.join(('{}', '{"msg":"downloading","bytes":100}',
                          '{"msg":"download complete","bytes":4096}',
                          '{"msg":"download test complete"}',
                          '{"msg":"upload complete","bytes":4096}'))
        records = transfer_summary(text)
        self.assertTrue(transfer_valid(0, records, 4096))

    def test_failed_partial_or_duplicate_transfers_are_not_success(self):
        download = {"msg": "download complete", "bytes": 4096}
        upload = {"msg": "upload complete", "bytes": 4096}
        for status, records, size in ((1, [download, upload], 4096),
                                      (0, [download], 4096),
                                      (0, [download, download], 4096),
                                      (0, [download, upload], 8192),
                                      ("timeout", [download, upload], 4096)):
            with self.subTest(status=status, records=records, size=size):
                self.assertFalse(transfer_valid(status, records, size))

    def test_speed_units_and_invalid_units(self):
        self.assertEqual(mbps("1000.00 Kbps"), 1)
        self.assertEqual(mbps("2.00 Gbps"), 2000)
        with self.assertRaises(ValueError):
            mbps("2.00 MB/s")

    def test_summary_excludes_invalid_transfer_and_uses_median(self):
        runs = []
        for status, speed in ((0, "1.00 Mbps"), (0, "3.00 Mbps"), (1, "99.00 Mbps")):
            runs.append({"algorithm": "bbr", "status": status,
                         "transfers": [{"msg": "download complete", "bytes": 4096, "speed": speed},
                                       {"msg": "upload complete", "bytes": 4096, "speed": speed}]})
        rows = summarize({"metadata": {"bytes_per_direction": 4096}, "runs": runs})
        self.assertEqual(rows[0]["valid"], 2)
        self.assertEqual(rows[0]["runs"], 3)
        self.assertEqual(rows[0]["download_mbps"], {"median": 2, "min": 1, "max": 3})

    def test_cleanup_only_uses_owned_names(self):
        network = Network()
        network.created = [network.names["c"], network.names["r"]]
        network.links = [network.prefix + "c"]
        with mock.patch("tests.network.gecko_bench.subprocess.run") as run:
            network.close()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [["ip", "netns", "delete", network.names["r"]],
                                    ["ip", "netns", "delete", network.names["c"]],
                                     ["ip", "link", "delete", network.prefix + "c"]])

    def test_summary_uses_per_run_size_wall_time_and_validity(self):
        records = [{"msg": direction + " complete", "bytes": 8192, "speed": "2.00 Mbps"} for direction in ("download", "upload")]
        runs = [{"algorithm": "geodesic", "status": 0, "valid": valid, "bytes_per_direction": 8192,
                 "wall_seconds": wall, "transfers": records} for valid, wall in ((True, 8), (True, 12), (False, 100))]
        row = summarize({"metadata": {"bytes_per_direction": 4096}, "runs": runs})[0]
        self.assertEqual(row["valid"], 2)
        self.assertEqual(row["wall_seconds"], {"median": 10, "min": 8, "max": 12})
        self.assertEqual(row["upload_mbps"]["median"], 2)


if __name__ == "__main__":
    unittest.main()
