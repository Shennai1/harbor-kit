from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.menu import run_menu


class CliTests(unittest.TestCase):
    def test_plan_json_never_runs_machine_checks_or_generates_keys(self):
        output = io.StringIO()
        with redirect_stdout(output), \
             patch("snellctl.__main__.collect", side_effect=AssertionError("machine check")), \
             patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("secret generation")):
            self.assertEqual(main(["plan", "--domain", "node.example.net", "--public-port", "24443", "--json"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["listeners"]["shadowtls_tcp"], "0.0.0.0:24443")
        self.assertFalse(report["environment_checked"])

    def test_invalid_plan_returns_error_without_raw_input(self):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = main(["plan", "--domain", "INJECTED;COMMAND"])
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("INJECTED", error.getvalue())

    def test_menu_refuses_noninteractive_stdin(self):
        for args in ([], ["menu"], ["menu", "--experimental"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                 patch("sys.stdin.isatty", return_value=False), \
                 patch("snellctl.__main__.run_menu", side_effect=AssertionError("unexpected menu")):
                self.assertEqual(main(args), 2)

    def test_default_command_opens_menu_in_terminal(self):
        with patch("sys.stdin.isatty", return_value=True), patch("snellctl.__main__.run_menu", return_value=0) as menu:
            self.assertEqual(main([]), 0)
        menu.assert_called_once_with()

    def test_doctor_still_reports_unsupported_platform(self):
        from snellctl.doctor import collect
        report = collect(system="Darwin", machine="arm64")
        output = io.StringIO()
        with patch("snellctl.__main__.collect", return_value=report), redirect_stdout(output):
            self.assertEqual(main(["doctor", "--json"]), 2)
        self.assertFalse(json.loads(output.getvalue())["platform_supported"])


class MenuTests(unittest.TestCase):
    def test_preview_with_custom_ports_and_exit(self):
        answers = ["2", "second", "node.example.net", "24443", "32001", "32443", "0"]
        output = io.StringIO()
        with patch("builtins.input", side_effect=answers), redirect_stdout(output), \
             patch("snellctl.menu.collect", side_effect=AssertionError("machine check")), \
             patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("secret generation")):
            self.assertEqual(run_menu(), 0)
        for text in ("second", "0.0.0.0:24443", "127.0.0.1:32001", "127.0.0.1:32443", "未执行"):
            self.assertIn(text, output.getvalue())

    def test_invalid_port_returns_to_menu_without_traceback(self):
        with patch("builtins.input", side_effect=["2", "", "node.example.net", "bad-port", "0"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 0)
        self.assertNotIn("Traceback", output.getvalue())
        self.assertNotIn("bad-port", output.getvalue())

    def test_unknown_choice_and_keyboard_interrupt_are_safe(self):
        with patch("builtins.input", side_effect=["99", KeyboardInterrupt]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 130)
        self.assertIn("请选择", output.getvalue())
        self.assertIn("未执行部署", output.getvalue())

    def test_eof_exits_without_changes(self):
        with patch("builtins.input", side_effect=EOFError), redirect_stdout(io.StringIO()):
            self.assertEqual(run_menu(), 130)

    def test_doctor_choice_renders_existing_diagnostics(self):
        from snellctl.doctor import collect
        report = collect(system="Darwin", machine="arm64")
        with patch("builtins.input", side_effect=["1", "0"]), \
             patch("snellctl.menu.collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 0)
        self.assertIn("只读环境检查", output.getvalue())


class ManagementMenuTests(unittest.TestCase):
    READ_ROUTES = (
        ("15", "1", "snellctl.maintenance.run_maintenance"),
        ("15", "2", "snellctl.packagestatus.run_package_status"),
        ("16", "1", "snellctl.uninstallplan.run_uninstall_plan"),
        ("16", "2", "snellctl.reinstallplan.run_reinstall_plan"),
    )
    CHANGE_ROUTES = (
        ("15", "3", "snellctl.packageplan.run_package_plan"),
        ("15", "4", "snellctl.packageinspection.run_package_review"),
        ("15", "5", "snellctl.packageupdate.run_package_update"),
        ("15", "6", "snellctl.packageresume.run_package_resume"),
        ("16", "3", "snellctl.uninstall.run_uninstall"),
        ("16", "4", "snellctl.reinstall.run_reinstall"),
    )

    def test_read_routes_reuse_cli_adapters_in_both_modes(self):
        for experimental in (False, True):
            for group, choice, target in self.READ_ROUTES:
                with self.subTest(experimental=experimental, target=target), \
                        patch(target, return_value=0) as run, \
                        patch("builtins.input", side_effect=[group, choice, "0", "0"]), \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(run_menu(experimental=experimental), 0)
                    if choice == "2" and group == "15":
                        run.assert_called_once_with(json_output=False)
                    else:
                        run.assert_called_once_with()

    def test_mutation_requires_opt_in_for_display_and_dispatch(self):
        for experimental in (False, True):
            for group, choice, target in self.CHANGE_ROUTES:
                with self.subTest(experimental=experimental, target=target), \
                        patch(target, return_value=0) as run, \
                        patch("builtins.input", side_effect=[group, choice, "0", "0"]), \
                        redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(run_menu(experimental=experimental), 0)
                    self.assertEqual(run.call_count, int(experimental))
                    if experimental:
                        run.assert_called_once_with()
                    else:
                        self.assertIn("请选择菜单中已有的编号", out.getvalue())
                        self.assertNotIn("3. 联网检查", out.getvalue())
                        self.assertNotIn("4. 下载升级包", out.getvalue())
                        self.assertNotIn("5. 实际 Debian", out.getvalue())
                        self.assertNotIn("6. 原更新任务受限恢复", out.getvalue())
                        self.assertNotIn("3. 卸载受管节点", out.getvalue())
                        self.assertNotIn("4. 成功卸载后的受控重装", out.getvalue())

    def test_browsing_and_returning_do_not_invoke_an_operation(self):
        with patch("snellctl.__main__.main") as dispatch, \
                patch("snellctl.menu.collect") as collect, \
                patch("builtins.input", side_effect=["15", "0", "16", "0", "0"]), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_menu(), 0)
        dispatch.assert_not_called()
        collect.assert_not_called()
        self.assertIn("组件维护（查询模式）", out.getvalue())
        self.assertIn("卸载与重装（查询模式）", out.getvalue())
        self.assertEqual(out.getvalue().count("snellctl（开发版）"), 3)

    def test_experimental_menu_labels_unvalidated_upgrade(self):
        with patch("builtins.input", side_effect=["15", "0", "16", "0", "0"]), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_menu(experimental=True), 0)
        for text in ("不提供 Snell/ShadowTLS 程序自动升级", "会停机，未实机验收",
                     "不重装，未实机验收", "操作仍需独立确认", "永久删除", "生成新密钥"):
            self.assertIn(text, out.getvalue())

    def test_cli_menu_opt_in_reaches_existing_backend_only_once(self):
        with patch("sys.stdin.isatty", return_value=True), \
                patch("builtins.input", side_effect=["15", "4", "0", "0"]), \
                patch("snellctl.packageinspection.run_package_review", return_value=0) as run, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(main(["menu", "--experimental"]), 0)
        run.assert_called_once_with()

    def test_no_update_success_returns_to_submenu_without_installing(self):
        with patch("builtins.input", side_effect=["15", "4", "0", "0"]), \
                patch("snellctl.packageinspection.run_package_review", return_value=0) as review, \
                patch("snellctl.packageupdate.run_package_update") as install, \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_menu(experimental=True), 0)
        review.assert_called_once_with()
        install.assert_not_called()
        self.assertEqual(out.getvalue().count("组件维护（实验入口已显示"), 2)

    def test_nonzero_action_exits_without_consuming_next_choice(self):
        for status in (1, 2, 130):
            for group, choice, target in self.READ_ROUTES + self.CHANGE_ROUTES:
                with self.subTest(status=status, target=target), \
                        patch(target, return_value=status) as run, \
                        patch("builtins.input", side_effect=[group, choice, "5"]) as read, \
                        redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(run_menu(experimental=True), status)
                    self.assertEqual(read.call_count, 2)
                    self.assertEqual(run.call_count, 1)
                    self.assertIn("菜单已退出", out.getvalue())
                    self.assertIn("不自动重试", out.getvalue())
                    self.assertEqual("操作可能已改变系统" in out.getvalue(),
                                     (group, choice, target) in self.CHANGE_ROUTES)

    def test_legacy_mutation_failure_also_exits_without_retry(self):
        for status in (1, 2, 130):
            with self.subTest(status=status), \
                    patch("snellctl.portchange.run_port_change", return_value=status) as run, \
                    patch("builtins.input", side_effect=["9", "9"]) as read, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(run_menu(experimental=True), status)
                self.assertEqual(read.call_count, 1)
                run.assert_called_once_with()

    def test_malformed_return_is_not_success_or_echoed(self):
        for status in (None, False, True, 0.0, -1, 3, "PRIVATE_RETURN"):
            with self.subTest(status=type(status).__name__), \
                    patch("snellctl.packageinspection.run_package_review", return_value=status), \
                    patch("builtins.input", side_effect=["15", "4"]), \
                    redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=True), 1)
                self.assertNotIn("PRIVATE_RETURN", out.getvalue())

    def test_unknown_submenu_input_is_not_a_command_or_echoed(self):
        for value in ("", "99", "ｙ", "package-update", "PRIVATE_INPUT;command"):
            with self.subTest(value=value), patch("snellctl.__main__.main") as dispatch, \
                    patch("builtins.input", side_effect=["15", value, "0", "0"]), \
                    redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=True), 0)
                dispatch.assert_not_called()
                self.assertIn("请选择菜单中已有的编号", out.getvalue())
                self.assertNotIn("PRIVATE_INPUT", out.getvalue())

    def test_submenu_eof_or_interrupt_exits_without_claiming_changes(self):
        for group in ("15", "16"):
            for error in (EOFError, KeyboardInterrupt):
                with self.subTest(group=group, error=error), \
                        patch("builtins.input", side_effect=[group, error]), \
                        redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(run_menu(experimental=True), 130)
                    self.assertIn("未执行部署或配置变更", out.getvalue())

    def test_interrupt_or_exception_during_mutation_warns_and_redacts(self):
        for error, code in ((EOFError, 130), (KeyboardInterrupt, 130), (RuntimeError, 1)):
            with self.subTest(error=error), \
                    patch("snellctl.packageupdate.run_package_update", side_effect=error("PRIVATE_ERROR")) as run, \
                    patch("builtins.input", side_effect=["15", "5"]), \
                    redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=True), code)
                run.assert_called_once_with()
                self.assertIn("操作可能已改变系统", out.getvalue())
                self.assertNotIn("PRIVATE_ERROR", out.getvalue())
                self.assertNotIn("Traceback", out.getvalue())
                self.assertNotIn("未执行部署", out.getvalue())

    def test_exception_in_main_readonly_action_is_redacted(self):
        with patch("snellctl.menu.collect", side_effect=RuntimeError("PRIVATE_ERROR")), \
                patch("builtins.input", side_effect=["1"]), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_menu(), 1)
        self.assertNotIn("PRIVATE_ERROR", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())

    def test_changes_warning_survives_return_to_main(self):
        with patch("snellctl.packageplan.run_package_plan", return_value=0), \
                patch("builtins.input", side_effect=["15", "3", "0", KeyboardInterrupt]), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_menu(experimental=True), 130)
        self.assertIn("操作可能已改变系统", out.getvalue())

    def test_menu_help_mentions_new_experimental_scope(self):
        with redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as error:
            main(["menu", "--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("联网维护", out.getvalue())
        self.assertIn("卸载重装", out.getvalue())

    def test_real_terminal_can_browse_and_leave_both_modes(self):
        for experimental in (False, True):
            with self.subTest(experimental=experimental):
                master, slave = pty.openpty()
                transcript = bytearray()
                try:
                    args = [sys.executable, "-E", "-s", "-B", "-m", "snellctl", "menu"]
                    if experimental:
                        args.append("--experimental")
                    with subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                          cwd=Path(__file__).resolve().parents[1],
                                          start_new_session=True) as child:
                        try:
                            answers = iter((b"15\n", b"0\n", b"16\n", b"0\n", b"0\n"))
                            prompt_count = 0
                            deadline = time.monotonic() + 10
                            while child.poll() is None:
                                if time.monotonic() >= deadline:
                                    self.fail("menu terminal timed out")
                                if select.select([master], [], [], 0.05)[0]:
                                    transcript.extend(os.read(master, 8192))
                                count = transcript.count("选择：".encode())
                                if count > prompt_count:
                                    self.assertEqual(count, prompt_count + 1)
                                    os.write(master, next(answers))
                                    prompt_count = count
                            child.wait(timeout=5)
                            while select.select([master], [], [], 0)[0]:
                                transcript.extend(os.read(master, 8192))
                            self.assertEqual(child.returncode, 0)
                            self.assertEqual(prompt_count, 5)
                        finally:
                            if child.poll() is None:
                                child.kill()
                                child.wait()
                    text = transcript.decode()
                    self.assertIn("组件维护（", text)
                    self.assertIn("卸载与重装（", text)
                    self.assertNotIn("Traceback", text)
                    self.assertEqual("5. 实际 Debian 包更新" in text, experimental)
                    self.assertEqual("3. 卸载受管节点" in text, experimental)
                finally:
                    os.close(master)
                    os.close(slave)
