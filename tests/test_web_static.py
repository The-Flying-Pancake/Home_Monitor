"""Static checks of the browser code for mistakes that fail silently."""

import glob
import os
import re
import unittest

from tests import _env

DIALOG = re.compile(r"await\s+(?:confirmDialog|promptDialog|openHostKeys)\(")


class CurrentTargetTests(unittest.TestCase):
    def test_current_target_read_before_awaiting_a_dialog(self):
        # The browser clears event.currentTarget once the click has been dispatched: read after an
        # awaited dialog it is null, and the handler stops without a message (Fix SNMP Apply, 2026-11-02).
        found = []
        for path in glob.glob(os.path.join(_env.ROOT, "web", "*.js")):
            lines = open(path, encoding="utf-8").read().splitlines()
            for i, line in enumerate(lines):
                if not DIALOG.search(line):
                    continue
                for j in range(i, min(i + 15, len(lines))):
                    if j > i and re.match(r"\s*\}\);?\s*$", lines[j]):
                        break
                    if re.search(r"\b(?:ev|event|e)\.currentTarget\b", lines[j]) and j > i:
                        found.append(f"{os.path.basename(path)}:{j + 1}")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
