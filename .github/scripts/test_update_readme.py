"""Exercise evolving repositories without touching the real course files."""

from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from update_readme import START, END, block, dashboard, generate, inventory, replace_block


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.write("README.md", f"Introduction personnelle.\n\n{START}\n{END}\n\nMa conclusion.\n")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def write(self, path, content="abc", tracked=True):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        if tracked:
            self.git("add", "--", path)

    def test_new_subject_and_untracked_files(self):
        self.write("Réseaux & systèmes/notes.md")
        self.write("Réseaux & systèmes/secret.txt", tracked=False)
        self.write(".github/assets/dashboard.svg")
        self.write(".github/scripts/update_readme.py")
        self.write("Réseaux & systèmes/.gitignore")
        self.write("Réseaux & systèmes/.cache/generated.txt")
        self.write(".gitignore", "*.tmp\n")
        self.write("Réseaux & systèmes/scratch.tmp", tracked=False)
        (self.root / "Matière vide").mkdir()
        subjects = inventory(self.root, {})
        self.assertEqual([(s.title, len(s.files)) for s in subjects], [("Réseaux & systèmes", 1)])
        self.assertEqual(subjects[0].size, 3)
        self.assertIn("./R%C3%A9seaux%20%26%20syst%C3%A8mes/", block(subjects))
        ET.fromstring(dashboard(subjects))

    def test_categories_and_sums(self):
        for path in ["A/notes.md", "A/Seance1", "A/support.pdf", "A/rendu.docx", "A/run.ps1", "A/configs/etc/issue.net", "A/lab.rep/database.gbf", "A/archive.zip"]:
            self.write(path)
        subject = inventory(self.root, {})[0]
        self.assertEqual(dict(subject.counts), {"Notes": 2, "Supports": 2, "Code & config": 2, "Autres": 2})
        self.assertEqual(subject.size, 24)

    def test_sizes_use_git_blobs_even_with_worktree_changes(self):
        self.write("A/notes.txt", "abc\n")
        (self.root / "A/notes.txt").write_bytes(b"changed without staging\r\n")
        self.assertEqual(inventory(self.root, {})[0].size, 4)

    def test_rename_delete_and_entry_fallback(self):
        self.write("Ancienne matière/README.md")
        first = inventory(self.root, {})[0]
        self.assertEqual(first.entry, "Ancienne matière/README.md")
        self.git("mv", "Ancienne matière", "Nouvelle matière")
        renamed = inventory(self.root, {"subjects": {"Nouvelle matière": {"entry": "absent.pdf"}}})[0]
        self.assertEqual(renamed.title, "Nouvelle matière")
        self.assertEqual(renamed.entry, "Nouvelle matière/README.md")
        self.git("rm", "-f", "Nouvelle matière/README.md")
        self.assertEqual(inventory(self.root, {}), [])

    def test_generated_output_preserves_prose_and_is_idempotent(self):
        self.write("A/notes.md")
        generate(self.root)
        first = (self.root / "README.md").read_bytes()
        self.assertTrue(first.startswith("Introduction personnelle.".encode()))
        self.assertTrue(first.endswith("Ma conclusion.\n".encode()))
        assets = list((self.root / ".github/assets").glob("*.svg"))
        before = {p.name: p.read_bytes() for p in assets}
        self.git("add", "--", "README.md", ".github/assets")
        generate(self.root)
        self.assertEqual(first, (self.root / "README.md").read_bytes())
        self.assertEqual(before, {p.name: p.read_bytes() for p in assets})

    def test_empty_repo_produces_valid_svg(self):
        ET.fromstring(dashboard([]))
        self.assertIn("0 matières", block([]))

    def test_custom_title_xml_markdown_and_exclusions(self):
        self.write("A/notes.md")
        self.write("build/output.bin")
        title = "Une matière très longue avec <XML> & [crochets] | et encore du texte"
        subjects = inventory(self.root, {"excluded_roots": ["build"], "subjects": {"A": {"title": title}}})
        self.assertEqual(len(subjects), 1)
        ET.fromstring(dashboard(subjects))
        self.assertIn("&lt;XML&gt;", block(subjects))
        self.assertIn("\\|", block(subjects))

    def test_root_notes_are_not_a_subject(self):
        self.write("notes.md")
        self.write("LICENSE")
        subjects = inventory(self.root, {})
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0].folder, "")
        self.assertIn("0 matières", block(subjects))
        self.assertIn("1 fichiers", block(subjects))

    def test_malformed_markers_refuse_to_overwrite(self):
        for original in ["No markers", END + START, START + START + END]:
            with self.assertRaises(ValueError):
                replace_block(original, "generated")


if __name__ == "__main__":
    unittest.main()
