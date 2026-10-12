"""Owner-editable guide articles stored under the panel data directory."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

GUIDE_NAME = "guide.json"
MAX_ARTICLES = 64
MAX_STEPS = 40
MAX_TITLE = 200
MAX_LEAD = 6000
MAX_NOTE = 4000
MAX_STEP_H = 300
MAX_STEP_P = 10000
MAX_HTML = 20000

ALLOWED_FONTS = (
    "Vazirmatn",
    "Tahoma",
    "Segoe UI",
    "Arial",
    "Georgia",
    "Times New Roman",
    "Courier New",
    "Consolas",
)

ALLOWED_TAGS = frozenset({"span", "b", "strong", "i", "em", "u", "br"})
ALLOWED_STYLE = frozenset(
    {
        "font-family",
        "font-size",
        "color",
        "background-color",
        "font-weight",
        "font-style",
        "text-decoration",
    }
)

_STYLE_SPLIT = re.compile(r";+")
_SIZE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,2})?(?:px|rem|em|%)$")
_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_WEIGHT_RE = re.compile(r"^(?:normal|bold|[1-9]00)$")
_DECOR_RE = re.compile(r"^(?:none|underline|line-through)$")
_FAMILY_RE = re.compile(r"^[A-Za-z0-9 ,\"'\-]+$")


class _GuideSanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self._stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in ALLOWED_TAGS:
            return
        if tag == "br":
            self._out.append("<br>")
            return
        clean: list[str] = []
        for key, value in attrs:
            key = (key or "").lower()
            if key != "style" or not value:
                continue
            style = _clean_style(value)
            if style:
                clean.append(f'style="{style}"')
        self._stack.append(tag)
        if clean:
            self._out.append(f"<{tag} {' '.join(clean)}>")
        else:
            self._out.append(f"<{tag}>")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("br",) or tag not in ALLOWED_TAGS:
            return
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()
            self._out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self._out.append(
            data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

    def handle_entityref(self, name: str) -> None:
        self._out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self._out.append(f"&#{name};")

    def result(self) -> str:
        while self._stack:
            self._out.append(f"</{self._stack.pop()}>")
        return "".join(self._out)


def _clean_style(raw: str) -> str:
    parts: list[str] = []
    for chunk in _STYLE_SPLIT.split(raw or ""):
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key not in ALLOWED_STYLE or not value or len(value) > 80:
            continue
        if any(ch in value for ch in ("<", ">", "{", "}", "\\", "(", ")")):
            continue
        if key in ("color", "background-color"):
            if not _COLOR_RE.fullmatch(value):
                continue
        elif key == "font-size":
            if not _SIZE_RE.fullmatch(value):
                continue
        elif key == "font-family":
            if not _FAMILY_RE.fullmatch(value):
                continue
            tokens = [t.strip(" \"'") for t in value.split(",") if t.strip()]
            if not tokens or any(t not in ALLOWED_FONTS for t in tokens):
                continue
            value = ", ".join(tokens)
        elif key == "font-weight":
            if not _WEIGHT_RE.fullmatch(value):
                continue
        elif key == "font-style":
            if value not in ("normal", "italic"):
                continue
        elif key == "text-decoration":
            if not _DECOR_RE.fullmatch(value):
                continue
        parts.append(f"{key}: {value}")
    return "; ".join(parts)


def sanitize_html(raw: str, limit: int) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if len(text) > limit:
        raise ValueError(f"متن نباید بیش از {limit} کاراکتر باشد")
    if "<" not in text and ">" not in text:
        # Plain text is stored as-is; the UI uses textContent for these fields.
        return text.replace("\x00", "")
    parser = _GuideSanitizer()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 — bad HTML from the editor
        raise ValueError("متن HTML نامعتبر است") from exc
    out = parser.result().strip()
    if len(out) > limit:
        raise ValueError(f"متن نباید بیش از {limit} کاراکتر باشد")
    return out


def _plain_limit(raw: str, limit: int, label: str) -> str:
    text = (raw or "").strip()
    if len(text) > limit:
        raise ValueError(f"{label} نباید بیش از {limit} کاراکتر باشد")
    return text


def _clean_style_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    font = str(raw.get("fontFamily") or "").strip()
    if font in ALLOWED_FONTS:
        out["fontFamily"] = font
    size = str(raw.get("fontSize") or "").strip()
    if _SIZE_RE.fullmatch(size):
        out["fontSize"] = size
    title = str(raw.get("titleSize") or "").strip()
    if _SIZE_RE.fullmatch(title):
        out["titleSize"] = title
    lead = str(raw.get("leadSize") or "").strip()
    if _SIZE_RE.fullmatch(lead):
        out["leadSize"] = lead
    step = str(raw.get("stepSize") or "").strip()
    if _SIZE_RE.fullmatch(step):
        out["stepSize"] = step
    line = str(raw.get("lineHeight") or "").strip()
    if re.fullmatch(r"^\d(?:\.\d{1,2})?$", line):
        out["lineHeight"] = line
    return out


def _clean_steps(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ValueError("لیست مراحل نامعتبر است")
    if len(raw) > MAX_STEPS:
        raise ValueError(f"حداکثر {MAX_STEPS} مرحله مجاز است")
    steps: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("هر مرحله باید عنوان و متن داشته باشد")
        h = sanitize_html(str(item.get("h") or ""), MAX_STEP_H)
        p = sanitize_html(str(item.get("p") or ""), MAX_STEP_P)
        if not h and not p:
            continue
        steps.append({"h": h, "p": p})
    if not steps:
        raise ValueError("حداقل یک مرحله لازم است")
    return steps


def normalize_article(raw: dict[str, Any]) -> dict[str, Any]:
    article_id = str(raw.get("id") or "").strip()
    if not re.fullmatch(r"^[a-z][a-z0-9_]{0,31}$", article_id):
        raise ValueError("شناسه آموزش نامعتبر است")
    title = sanitize_html(str(raw.get("title") or ""), MAX_TITLE)
    if not title:
        raise ValueError("عنوان آموزش لازم است")
    lead = sanitize_html(str(raw.get("lead") or ""), MAX_LEAD)
    note = sanitize_html(str(raw.get("note") or ""), MAX_NOTE)
    group = _plain_limit(str(raw.get("group") or ""), 40, "گروه")
    nav = sanitize_html(str(raw.get("nav") or title), MAX_TITLE)
    return {
        "id": article_id,
        "group": group,
        "nav": nav,
        "title": title,
        "lead": lead,
        "note": note,
        "steps": _clean_steps(raw.get("steps")),
        "style": _clean_style_map(raw.get("style")),
    }


def guide_path(data_dir: Path) -> Path:
    return Path(data_dir) / GUIDE_NAME


def read_guide_store(data_dir: Path) -> dict[str, Any]:
    path = guide_path(data_dir)
    if not path.is_file():
        return {"version": 1, "articles": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"version": 1, "articles": {}}
    articles = data.get("articles") if isinstance(data, dict) else None
    if not isinstance(articles, dict):
        return {"version": 1, "articles": {}}
    cleaned: dict[str, Any] = {}
    for key, value in articles.items():
        if not isinstance(value, dict):
            continue
        try:
            item = normalize_article({**value, "id": key})
        except ValueError:
            continue
        cleaned[item["id"]] = item
        if len(cleaned) >= MAX_ARTICLES:
            break
    return {"version": 1, "articles": cleaned}


def write_guide_article(data_dir: Path, article: dict[str, Any]) -> dict[str, Any]:
    item = normalize_article(article)
    store = read_guide_store(data_dir)
    store["articles"][item["id"]] = item
    if len(store["articles"]) > MAX_ARTICLES:
        raise ValueError(f"حداکثر {MAX_ARTICLES} آموزش قابل ذخیره است")
    path = guide_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return item


def delete_guide_article(data_dir: Path, article_id: str) -> bool:
    store = read_guide_store(data_dir)
    if article_id not in store["articles"]:
        return False
    del store["articles"][article_id]
    path = guide_path(data_dir)
    if not store["articles"]:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return True
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return True


def guide_public_view(data_dir: Path) -> dict[str, Any]:
    store = read_guide_store(data_dir)
    return {
        "fonts": list(ALLOWED_FONTS),
        "articles": store["articles"],
    }
