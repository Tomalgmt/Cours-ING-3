"""Generate a GitHub-native course dashboard from the Git index (stdlib only)."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from html import escape
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import quote

START, END = "<!-- AUTO:START -->", "<!-- AUTO:END -->"
CATEGORIES = ("Notes", "Supports", "Code & config", "Autres")
COLORS = ("#65e3da", "#ab9bff", "#ffca80", "#8a9dbb")
NOTES = {".md", ".txt", ".rst", ".adoc", ".org", ".tex"}
SUPPORTS = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".odt", ".odp"}
CODE = {
    ".py", ".sh", ".ps1", ".bat", ".cmd", ".c", ".h", ".cpp", ".hpp",
    ".java", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".sql", ".asm",
    ".ipynb", ".json", ".yaml", ".yml", ".toml", ".conf", ".cfg", ".ini",
    ".xml", ".html", ".css", ".tf", ".rules",
}
ROOT_META = {"readme", "license", "licence", "copying", "contributing", "code_of_conduct", "security", "agents"}


@dataclass(frozen=True)
class Resource:
    path: str
    size: int
    category: str


@dataclass
class Subject:
    folder: str
    title: str
    description: str
    entry: str
    files: list[Resource]

    @property
    def counts(self) -> Counter:
        return Counter(item.category for item in self.files)

    @property
    def size(self) -> int:
        return sum(item.size for item in self.files)


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args], input=data, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def category(path: str) -> str:
    p = PurePosixPath(path)
    suffix = p.suffix.lower()
    if suffix in SUPPORTS:
        return "Supports"
    if suffix in NOTES or (not suffix and re.match(r"s[ée]ance\s*\d", p.name, re.I)):
        return "Notes"
    if suffix in CODE or "configs" in p.parts or p.name.lower() in {"dockerfile", "makefile"}:
        return "Code & config"
    return "Autres"


def inventory(root: Path, config: dict) -> list[Subject]:
    records = git(root, "ls-files", "--stage", "-z").split(b"\0")
    paths: dict[str, str] = {}
    excluded = set(config.get("excluded_roots", []))
    for record in filter(None, records):
        header, raw_path = record.split(b"\t", 1)
        mode, oid, stage = header.split()
        if stage != b"0":
            raise ValueError("Résoudre les conflits Git avant de générer le README.")
        path = raw_path.decode("utf-8")
        parts = PurePosixPath(path).parts
        # Ignore symlinks, submodules, hidden metadata and dashboard infrastructure.
        if mode not in {b"100644", b"100755"} or any(p.startswith(".") for p in parts):
            continue
        if parts[0] in excluded or (len(parts) == 1 and PurePosixPath(path).stem.lower() in ROOT_META):
            continue
        paths[path] = oid.decode("ascii")
    if not paths:
        return []
    # Git blob sizes avoid CRLF differences between Windows and Linux; no file is executed.
    oids = sorted(set(paths.values()))
    sizes = dict(
        (oid, int(size)) for oid, size in (
            line.split() for line in git(
                root, "cat-file", "--batch-check=%(objectname) %(objectsize)",
                data=("\n".join(oids) + "\n").encode("ascii"),
            ).decode("ascii").splitlines()
        )
    )
    grouped: dict[str, list[Resource]] = {}
    for path, oid in sorted(paths.items()):
        folder = path.split("/", 1)[0] if "/" in path else ""
        grouped.setdefault(folder, []).append(Resource(path, sizes[oid], category(path)))
    subjects = []
    for folder, files in grouped.items():
        options = config.get("subjects", {}).get(folder, {})
        entry = ""
        candidates = [options.get("entry", ""), "README.md", "readme.md"]
        for candidate in filter(None, candidates):
            full = f"{folder}/{candidate}" if folder else candidate
            if full in paths:
                entry = full
                break
        subjects.append(Subject(
            folder, options.get("title", folder or "À la racine"),
            options.get("description", "Notes, exercices et ressources de la matière." if folder else "Ressources placées à la racine du dépôt."),
            entry, files,
        ))
    return sorted(subjects, key=lambda s: s.title.casefold())


def number(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def volume(size: int) -> str:
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1000 or unit == "To":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}".replace(".", ",")
        size /= 1000
    raise AssertionError("unreachable")


def md(value: str) -> str:
    value = escape(value).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()!|])", r"\\\1", value)


def link(path: str) -> str:
    return "./" + quote(path, safe="/")


def text(x: float, y: float, value: str, size: int = 18, fill: str = "#edf3ff", **attrs) -> str:
    extras = " ".join(f'{k.replace("_", "-")}="{escape(str(v), quote=True)}"' for k, v in attrs.items())
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" {extras}>{escape(str(value))}</text>'


def rect(x: float, y: float, width: float, height: float, fill: str, radius: int = 18, **attrs) -> str:
    extras = " ".join(f'{k.replace("_", "-")}="{escape(str(v), quote=True)}"' for k, v in attrs.items())
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" fill="{fill}" {extras}/>'


def svg(body: list[str], height: int, title: str, desc: str) -> str:
    return '\n'.join([
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" viewBox="0 0 1200 {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>',
        '<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#101b31"/><stop offset="1" stop-color="#111326"/></linearGradient>',
        '<linearGradient id="accent"><stop stop-color="#65e3da"/><stop offset="1" stop-color="#ab9bff"/></linearGradient></defs>',
        '<g font-family="Segoe UI, Inter, Arial, sans-serif">',
        rect(0, 0, 1200, height, "url(#bg)", 26), *body, '</g></svg>', '',
    ])


def banner() -> str:
    body = [
        rect(44, 38, 276, 30, "#1e3548", 15),
        text(61, 59, "CARNET D’INGÉNIEUR  /  VOL. 03", 13, "#83eee4", letter_spacing="1.2"),
        text(44, 135, "Apprendre.", 57, font_weight="750"),
        text(44, 200, "Expérimenter.", 57, font_weight="750"),
        text(44, 265, "Documenter.", 57, "#65e3da", font_weight="750"),
        text(47, 322, "COURS   /   EXERCICES   /   LABORATOIRES", 15, "#a6b7d1", letter_spacing="2"),
        '<circle cx="976" cy="180" r="142" fill="none" stroke="#2b3550"/>',
        '<circle cx="976" cy="180" r="112" fill="none" stroke="#26344c" stroke-dasharray="4 12"/>',
        '<path d="M735 94H837L870 127H1110M743 259H820L860 219H1137" fill="none" stroke="#405878" stroke-width="2"/>',
        text(886, 233, "03", 160, "#263550", font_weight="800"),
    ]
    for x, y, label, color, width in [(706, 65, "~/cours", "#65e3da", 195), (790, 148, "./travaux-pratiques", "#ab9bff", 322), (733, 239, "git add connaissances", "#ffca80", 332)]:
        body += [rect(x, y, width, 62, "#152039", 12, stroke="#354565"),
                 text(x + 20, y + 39, label, 21, color, font_family="Consolas, monospace")]
    return svg(body, 364, "Cours ING 3", "Troisième année d’ingénieur. Apprendre, expérimenter, documenter. Un carnet de cours, exercices et laboratoires en évolution.")


def dashboard(subjects: list[Subject]) -> str:
    files = [f for s in subjects for f in s.files]
    counts = Counter(f.category for f in files)
    total = len(files)
    height = max(644, 346 + len(subjects) * 57)
    body = [text(40, 49, "LE DÉPÔT EN CHIFFRES", 17, "#a6b7d1", letter_spacing="2"),
            text(1160, 48, "UN INSTANTANÉ, PAS UN TAUX DE RÉUSSITE", 12, "#a6b7d1", text_anchor="end")]
    stats = [(str(sum(bool(s.folder) for s in subjects)), "MATIÈRES", "détectées automatiquement"),
             (number(total), "FICHIERS", "suivis par Git"),
             (str(sum(PurePosixPath(f.path).suffix.lower() == ".pdf" for f in files)), "PDF", "supports et rendus"),
             (volume(sum(f.size for f in files)), "VOLUME", "hors historique Git")]
    for i, (value, label, hint) in enumerate(stats):
        x = 40 + i * 286
        body += [rect(x, 75, 262, 139, "#17243c", 16, stroke="#2d3d57"),
                 rect(x + 20, 95, 24, 3, COLORS[i], 1),
                 text(x + 20, 147, value, 40, font_weight="700"),
                 text(x + 20, 176, label, 12, COLORS[i], letter_spacing="1.8"),
                 text(x + 20, 198, hint, 12, "#a6b7d1")]
    body += [rect(40, 240, 660, height - 281, "#141e33", 16, stroke="#293852"),
             rect(722, 240, 438, height - 281, "#141e33", 16, stroke="#293852"),
             text(62, 278, "La carte des matières", 23, font_weight="650"),
             text(62, 304, "Nombre de fichiers par matière", 14, "#a6b7d1"),
             text(747, 278, "Dans le sac", 23, font_weight="650")]
    maximum = max((len(s.files) for s in subjects), default=1)
    for i, subject in enumerate(sorted(subjects, key=lambda s: (-len(s.files), s.title.casefold()))):
        y = 340 + i * 57
        title = subject.title if len(subject.title) <= 43 else subject.title[:40] + "…"
        body += [text(62, y, title, 16), text(675, y, number(len(subject.files)), 16, "#b7c7df", text_anchor="end"),
                 rect(62, y + 11, 613, 9, "#29354e", 4)]
        x = 62.0
        for cat, color in zip(CATEGORIES, COLORS):
            width = subject.counts[cat] / maximum * 613
            if width:
                body.append(rect(round(x, 2), y + 11, round(width, 2), 9, color, 0))
                x += width
    if not subjects:
        body.append(text(62, 357, "La première matière arrive bientôt.", 18, "#a6b7d1"))
    circumference = 2 * math.pi * 68
    body.append('<circle cx="941" cy="383" r="68" fill="none" stroke="#29354e" stroke-width="20"/>')
    offset = 0.0
    for cat, color in zip(CATEGORIES, COLORS):
        length = (counts[cat] / total * circumference) if total else 0
        if length:
            body.append(f'<circle cx="941" cy="383" r="68" fill="none" stroke="{color}" stroke-width="20" stroke-dasharray="{length:.4f} {circumference-length:.4f}" stroke-dashoffset="{-offset:.4f}" transform="rotate(-90 941 383)"/>')
        offset += length
    body += [text(941, 387, number(total), 35, text_anchor="middle", font_weight="700"),
             text(941, 412, "fichiers", 14, "#a6b7d1", text_anchor="middle")]
    for i, (cat, color) in enumerate(zip(CATEGORIES, COLORS)):
        y = 489 + i * 27
        percent = (counts[cat] / total * 100) if total else 0
        body += [rect(748, y - 10, 10, 10, color, 3), text(770, y, cat, 15, "#c5d3e8"),
                 text(1135, y, f"{counts[cat]}  /  {percent:.1f} %".replace(".", ","), 15, text_anchor="end")]
    body.append(text(40, height - 14, "Calculé depuis les fichiers versionnés · Notes, supports, code, configurations et ressources de laboratoire", 12, "#9cafcb"))
    desc = f"{len(stats)} indicateurs : {stats[0][0]} matières, {total} fichiers, {stats[2][0]} PDF, {stats[3][0]}. "
    desc += "; ".join(f"{s.title} : {len(s.files)} fichiers" for s in subjects)
    return svg(body, height, "Tableau de bord des cours", desc)


def block(subjects: list[Subject]) -> str:
    files = [f for s in subjects for f in s.files]
    counts = Counter(f.category for f in files)
    lines = [START, "", "## Le dépôt en chiffres", "",
             '<a href=".github/assets/dashboard.svg"><img src=".github/assets/dashboard.svg" alt="Statistiques du dépôt : matières, fichiers, PDF, volume et répartition. Cliquer pour agrandir ; détails dans le tableau ci-dessous." width="100%"></a>', "",
             f"**{sum(bool(s.folder) for s in subjects)} matières** · **{number(len(files))} fichiers** · **{volume(sum(f.size for f in files))} versionnés**", "",
             "Les barres montrent le volume de fichiers, pas l’avancement des cours. Les archives et données de laboratoire comptent aussi.", "",
             "## Les matières", "",
             "Chaque matière a son espace. Le lien **Ouvrir** mène au document d’entrée lorsqu’il existe, sinon au dossier.", "",
             "| Matière | Notes | Supports | Code & config | Autres | Volume | Entrée |",
             "| :-- | --: | --: | --: | --: | --: | :-- |"]
    for s in subjects:
        folder = link(s.folder + "/") if s.folder else "./"
        entry = link(s.entry) if s.entry else folder
        values = " | ".join(str(s.counts[c]) for c in CATEGORIES)
        lines.append(f"| **[{md(s.title)}]({folder})**<br><sub>{md(s.description)}</sub> | {values} | {volume(s.size)} | [Ouvrir ↗]({entry}) |")
    if not subjects:
        lines.append("| Les premières matières arrivent bientôt. | 0 | 0 | 0 | 0 | 0 o | — |")
    values = " | ".join(f"**{counts[c]}**" for c in CATEGORIES)
    lines += [f"| **Total** | {values} | **{volume(sum(f.size for f in files))}** | |", "",
              "<sub>Notes : Markdown, texte et formats similaires. Supports : PDF, documents et présentations. Code & config : scripts, sources et paramètres. Autres : archives, binaires, images et fichiers de projet.</sub>", "", END]
    return "\n".join(lines)


def replace_block(original: str, generated: str) -> str:
    if original.count(START) != 1 or original.count(END) != 1 or original.index(START) > original.index(END):
        raise ValueError("Le README doit contenir exactement une paire ordonnée AUTO:START / AUTO:END.")
    start, end = original.index(START), original.index(END) + len(END)
    return original[:start] + generated + original[end:]


def generate(root: Path, output: Path | None = None) -> list[Subject]:
    root = root.resolve()
    output = (output or root).resolve()
    # --output permits a read-only inventory of a repository and a separate preview.
    config_path = output / ".github/readme-config.json"
    if not config_path.exists():
        config_path = root / ".github/readme-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    subjects = inventory(root, config)
    readme_path = output / "README.md"
    original = readme_path.read_text(encoding="utf-8")
    updated = replace_block(original, block(subjects))
    assets = output / ".github/assets"
    assets.mkdir(parents=True, exist_ok=True)
    for path, content in [(readme_path, updated), (assets / "banner.svg", banner()), (assets / "dashboard.svg", dashboard(subjects))]:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8", newline="\n")
    return subjects


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = generate(args.root, args.output)
    print(f"README actualisé : {sum(bool(s.folder) for s in result)} matières, {sum(len(s.files) for s in result)} fichiers.")
