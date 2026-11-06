# SPDX-License-Identifier: MIT-0
"""Offline checks for current release documentation."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = (
    "README.md", "CHANGELOG.md", "docs/obfuscation.md",
    "docs/carakan.md", "docs/presto.md", "docs/trident.md",
    "docs/release-v1.1.0.md",
    "docs/servo.md",
    "docs/tasman.md",
    "docs/mariner.md", "docs/release-v1.2.0.md",
    "docs/designs/00-COMMON.md", "docs/designs/03-MARINER.md",
    "docs/designs/03-MARINER-IMPLEMENTATION.md",
)


class ReleaseDocumentTests(unittest.TestCase):
    def test_local_links_resolve(self):
        for name in DOCUMENTS:
            path = ROOT / name
            for target in re.findall(r"\[[^\]]*\]\(([^\s)]+)\)", path.read_text(encoding="utf-8")):
                url = urlsplit(target)
                if url.scheme or url.netloc or not url.path:
                    continue
                with self.subTest(document=name, target=target):
                    self.assertTrue((path.parent / unquote(url.path)).is_file())

    def test_carakan_guide_only_describes_current_format(self):
        guide = (ROOT / "docs/carakan.md").read_text(encoding="utf-8")
        source = (ROOT / "extras/obfs/carakan_tans.go").read_text(encoding="utf-8")
        domain = re.search(r'"(oh-my-hysteria/carakan/v\d+)"', source).group(1)
        self.assertIn(domain, guide)
        self.assertNotRegex(guide, r"(?m)carakan/v[12]\b|^#{1,6} .*\bv[12]\b")

    def test_status_warning_is_not_repeated_across_guides(self):
        count = sum((ROOT / name).read_text(encoding="utf-8").count("高度实验性") for name in DOCUMENTS)
        self.assertLessEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
