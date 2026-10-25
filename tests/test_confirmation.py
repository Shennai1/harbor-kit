import unittest

from snellctl.installer import confirm
from test_installer import Console


class ConfirmationTests(unittest.TestCase):
    def test_only_ascii_y_authorizes(self):
        for answer in ("y", "Y", " y ", "\tY\t"):
            ui = Console([answer])
            self.assertTrue(confirm(ui, "确认更换端口 443？"))
            self.assertIn("[y/n]（默认 n）", ui.prompts[0])

    def test_no_blank_invalid_or_old_chinese_authorization(self):
        for answer in ("", " ", "n", "N", "yes", "true", "1", "ｙ", "已重连", "更换端口 443"):
            with self.subTest(answer=answer):
                self.assertFalse(confirm(Console([answer]), "继续？"))

    def test_eof_and_interrupt_are_not_authorization(self):
        for error in (EOFError, KeyboardInterrupt):
            with self.assertRaises(error):
                confirm(Console([error()]), "继续？")
