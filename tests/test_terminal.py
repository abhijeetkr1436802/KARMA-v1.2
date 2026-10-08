import unittest
from backend.sensors.terminal import TerminalInput


class TerminalTests(unittest.TestCase):
    def test_crlf_and_history(self):
        terminal = TerminalInput()
        commands = []
        for char in 'pwd\r\nwhoami\r\x1b[A\r':
            _, command, _ = terminal.feed(char, '# ')
            if command is not None:
                commands.append(command)
        self.assertEqual(commands, ['pwd', 'whoami', 'whoami'])

    def test_edit_cancel_and_eof(self):
        terminal = TerminalInput()
        for char in 'pwX\x7fd':
            terminal.feed(char, '# ')
        self.assertEqual(terminal.feed('\r', '# ')[1], 'pwd')
        terminal.feed('x', '# ')
        terminal.feed('\x03', '# ')
        self.assertEqual(terminal.buffer, '')
        self.assertTrue(terminal.feed('\x04', '# ')[2])

    def test_input_is_bounded(self):
        terminal = TerminalInput()
        for _ in range(8192):
            terminal.feed('x', '# ')
        self.assertTrue(terminal.feed('x', '# ')[2])
