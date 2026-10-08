import unittest
from unittest.mock import patch

import run


class LauncherTests(unittest.TestCase):
    def test_missing_dependency_has_actionable_error(self):
        with patch.object(run.importlib.util, 'find_spec', side_effect=lambda name: None if name == 'pypdf' else object()):
            with self.assertRaises(SystemExit) as result:
                run.check_dependencies()
            self.assertIn('pypdf', str(result.exception))
            self.assertIn('requirements.txt', str(result.exception))
            self.assertIn(run.sys.executable, str(result.exception))
