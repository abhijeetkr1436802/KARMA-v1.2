"""Bounded terminal input handling for the simulated SSH shell."""
class TerminalInput:
    def __init__(self):
        self.buffer = ''
        self.history = []
        self.index = 0
        self.draft = ''
        self.escape = ''
        self.was_cr = False

    def feed(self, char, prompt):
        """Return terminal output, a submitted command, and an EOF flag."""
        if self.escape:
            self.escape += char
            if self.escape in ('\x1b[', '\x1bO'):
                return '', None, False
            if self.escape in ('\x1b[A', '\x1bOA', '\x1b[B', '\x1bOB'):
                if self.index == len(self.history):
                    self.draft = self.buffer
                self.index = max(0, min(len(self.history), self.index + (-1 if char == 'A' else 1)))
                self.buffer = self.history[self.index] if self.index < len(self.history) else self.draft
                self.escape = ''
                return '\r\x1b[2K' + prompt + self.buffer, None, False
            if char.isalpha() or char == '~' or len(self.escape) >= 8:
                self.escape = ''
            return '', None, False
        if char == '\x1b':
            self.escape = char
            return '', None, False
        if char == '\n' and self.was_cr:
            self.was_cr = False
            return '', None, False
        self.was_cr = char == '\r'
        if char in ('\r', '\n'):
            command, self.buffer = self.buffer, ''
            if command.strip():
                self.history.append(command)
                self.history = self.history[-100:]
            self.index, self.draft = len(self.history), ''
            return '\r\n', command, False
        if char == '\x04':
            return ('logout\r\n', None, True) if not self.buffer else ('\a', None, False)
        if char == '\x03':
            self.buffer, self.draft, self.index = '', '', len(self.history)
            return '^C\r\n' + prompt, None, False
        if char in ('\x7f', '\x08'):
            if self.buffer:
                self.buffer = self.buffer[:-1]
                return '\b \b', None, False
        elif char == '\t':
            return '\a', None, False
        elif char.isprintable():
            if len(self.buffer) >= 8192:
                return '\r\nInput limit exceeded.\r\n', None, True
            self.buffer += char
            return char, None, False
        return '', None, False
