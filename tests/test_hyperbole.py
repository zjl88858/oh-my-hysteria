# SPDX-License-Identifier: MIT-0

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import hyperbole


class BuildToolTests(unittest.TestCase):
    def test_fork_module_paths(self):
        repository = "github.com/zjl88858/oh-my-hysteria"
        for module in ("app", "core", "extras"):
            with self.subTest(module=module):
                go_mod = (hyperbole.PROJECT_ROOT / module / "go.mod").read_text(encoding="utf-8")
                self.assertEqual(go_mod.splitlines()[0], f"module {repository}/{module}/v2")
        self.assertEqual(hyperbole.APP_SRC_CMD_PKG, f"{repository}/app/v2/cmd")

    def test_default_version_ignores_upstream_tags_and_environment(self):
        with mock.patch.dict(os.environ, {"HY_APP_VERSION": "v2.99.0"}, clear=True):
            with mock.patch.object(subprocess, "check_output") as git:
                self.assertEqual(hyperbole.get_app_version(), "v1.0.0")
                git.assert_not_called()

    def test_version_override(self):
        with mock.patch.dict(os.environ, {"OH_MY_HYSTERIA_VERSION": "v1.1.0-test"}):
            self.assertEqual(hyperbole.get_app_version(), "v1.1.0-test")

    def test_go_version_parser(self):
        self.assertEqual(hyperbole.parse_go_version("go1.26.0"), (1, 26, 0))
        self.assertEqual(hyperbole.parse_go_version("go version go1.26 windows/amd64"), (1, 26, 0))
        self.assertIsNone(hyperbole.parse_go_version("unknown"))

    def test_platform_override(self):
        with mock.patch.dict(os.environ, {"OH_MY_HYSTERIA_PLATFORMS": "linux/amd64,windows/arm64"}):
            self.assertEqual(hyperbole.get_app_platforms(), [("linux", "amd64"), ("windows", "arm64")])

    def test_native_platform_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(hyperbole, "get_current_os_arch", return_value=("windows", "amd64")):
                self.assertEqual(hyperbole.get_app_platforms(), [("windows", "amd64")])

    def test_build_without_git(self):
        with mock.patch.object(hyperbole, "check_command", return_value=True) as check:
            with mock.patch.object(hyperbole, "get_required_go_version", return_value=(1, 26, 0)):
                with mock.patch.object(hyperbole, "get_go_version", return_value=(1, 26, 0)):
                    self.assertTrue(hyperbole.check_build_env())
                    check.assert_called_once_with(["go", "version"])

    def test_failed_build_environment_exits_nonzero(self):
        with mock.patch.object(hyperbole, "check_build_env", return_value=False):
            with self.assertRaises(SystemExit) as caught:
                hyperbole.cmd_build()
            self.assertEqual(caught.exception.code, 1)

    def test_failed_tests_exit_nonzero_and_test_all_modules(self):
        with mock.patch.object(hyperbole, "check_build_env", return_value=True):
            with mock.patch.object(subprocess, "check_call", side_effect=subprocess.CalledProcessError(1, "go test")) as run:
                with self.assertRaises(SystemExit) as caught:
                    hyperbole.cmd_test()
                self.assertEqual(caught.exception.code, 1)
                self.assertEqual(run.call_count, 3)

    def test_release_build_names_metadata_and_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.multiple(
                hyperbole,
                BUILD_DIR=directory,
                check_build_env=mock.Mock(return_value=True),
                get_app_version=mock.Mock(return_value="v1.0.0"),
                get_app_commit=mock.Mock(return_value="test-commit"),
                get_toolchain=mock.Mock(return_value="go1.26.0 windows/amd64"),
                get_lib_version=mock.Mock(return_value="test-quic"),
                get_app_platforms=mock.Mock(return_value=[("windows", "amd64"), ("linux", "arm64")]),
            ):
                with mock.patch.object(subprocess, "check_call") as run:
                    hyperbole.cmd_build(release=True)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(Path(commands[0][3]).name, "oh-my-hysteria-windows-amd64.exe")
            self.assertEqual(Path(commands[1][3]).name, "oh-my-hysteria-linux-arm64")
            self.assertIn(".appVersion=v1.0.0", commands[0][5])
            self.assertIn("-trimpath", commands[0])
            for name in ("LICENSE.md", "LICENSE-THIRD-PARTY.md"):
                self.assertEqual((Path(directory) / name).read_bytes(), (hyperbole.PROJECT_ROOT / name).read_bytes())
            self.assertEqual((Path(directory) / "LICENSE-tquic.txt").read_bytes(),
                             (hyperbole.PROJECT_ROOT / "third_party/tquic/LICENSE").read_bytes())
            for project in ("kcc", "ucp"):
                self.assertEqual((Path(directory) / f"LICENSE-geodesic-{project}.txt").read_bytes(),
                                 (hyperbole.PROJECT_ROOT / f"third_party/geodesic/LICENSE-{project}").read_bytes())


if __name__ == "__main__":
    unittest.main()
