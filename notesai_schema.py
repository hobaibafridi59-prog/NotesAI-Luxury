"""Schema normalisation for NotesAI page understanding and diagram specs.

The AI returns a compact JSON document. This module is deliberately defensive:
it never trusts the model's structure, keeps every string bounded, and falls
back to the existing title/sections model when older responses are received.
"""

from __future__ import annotations

import difflib
import re
from typing import Any

SCHEMA_VERSION = 2
MAX_BLOCKS_PER_PAGE = 240
MAX_DIAGRAMS_PER_PAGE = 24
MAX_SCENE_ELEMENTS = 500
MAX_TEXT = 12000

PLANETS = (
    "Mercury",
    "Venus",
    "Earth",
    "Mars",
    "Jupiter",
    "Saturn",
    "Uranus",
    "Neptune",
)

_BLOCK_TYPES = {
    "heading", "paragraph", "list", "table", "callout", "question",
    "formula", "flow", "diagram", "uncertain", "page_break",
}

_DIAGRAM_CATEGORIES = {
    "astronomy", "biology", "chemistry", "physics", "mathematics",
    "geography", "engineering", "flowchart", "chart", "education", "other",
}


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()[:limit]


def _as_int(value: Any, default: int = 0, low: int | None = None, high: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if low is not None:
        number = max(low, number)
    if high is not None:
        number = min(high, number)
    return number


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return max(0.0, min(1.0, number))


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _unique_id(prefix: str, used: set[str], preferred: Any = None) -> str:
    raw = clean_text(preferred, 80)
    raw = re.sub(r"[^A-Za-z0-9_-]+", "", raw)
    if raw and raw not in used:
        used.add(raw)
        return raw
    index = 1
    while f"{prefix}{index}" in used:
        index += 1
    result = f"{prefix}{index}"
    used.add(result)
    return result


def canonical_planet_name(name: Any) -> tuple[str, bool]:
    """Return (canonical name, corrected). Only clear spelling variants change."""
    raw = clean_text(name, 80)
    if not raw:
        return "", False
    lowered = raw.casefold()
    for planet in PLANETS:
        if lowered == planet.casefold():
            return planet, False
    match = difflib.get_close_matches(raw, PLANETS, n=1, cutoff=0.78)
    if match:
        return match[0], True
    return raw, False


def _clean_table_cell(cell: str) -> str:
    """Remove a leading bullet/number marker from a table cell."""
    value = clean_text(cell, 2000)
    return re.sub(r"^(?:[•\-*·]|\d+[.)])\s+", "", value).strip()


def _parse_pipe_table(text: str) -> tuple[list[str], list[list[str]]]:
    lines = [line.strip() for line in clean_text(text).splitlines() if line.strip()]
    rows: list[list[str]] = []
    for line in lines:
        if "|" not in line:
            continue
        cells = [_clean_table_cell(cell) for cell in line.strip("|").split("|")]
        if cells and not all(re.fullmatch(r":?-{2,}:?", cell or "") for cell in cells):
            rows.append(cells)
    if not rows:
        return [], []
    width = max(len(row) for row in rows)
    columns = [f"Column {index + 1}" for index in range(width)]
    if len(rows[0]) == width:
        first = rows[0]
        # A header is only assumed when the first row has no obvious numeric id.
        if not any(re.fullmatch(r"\d+[.)]?", cell or "") for cell in first):
            columns = first
            rows = rows[1:]
    return columns, rows


def _normalise_table(raw: dict, index: int, used: set[str]) -> dict:
    columns = [clean_text(cell, 300) for cell in _as_list(raw.get("columns"))]
    rows: list[list[str]] = []
    for row in _as_list(raw.get("rows")):
        if isinstance(row, dict):
            cells = [row.get(column) for column in columns] if columns else list(row.values())
        elif isinstance(row, (list, tuple)):
            cells = list(row)
        else:
            cells = [row]
        rows.append([clean_text(cell, 2000) for cell in cells])
    if not columns and rows:
        columns = [f"Column {i + 1}" for i in range(max(len(row) for row in rows))]
    if not rows and (raw.get("content") or raw.get("text")):
        columns, rows = _parse_pipe_table(raw.get("content") or raw.get("text"))
    return {
        "id": _unique_id("b", used, raw.get("id") or f"table-{index + 1}"),
        "type": "table",
        "title": clean_text(raw.get("title"), 500),
        "columns": columns[:20],
        "rows": rows[:200],
        "header": bool(raw.get("header", True)),
        "align": [clean_text(item, 20) for item in _as_list(raw.get("align"))][:20],
    }


def _normalise_block(raw: Any, index: int, used: set[str]) -> dict | None:
    if not isinstance(raw, dict):
        return None
    block_type = clean_text(raw.get("type"), 40).lower()
    if block_type not in _BLOCK_TYPES:
        block_type = "paragraph" if (raw.get("text") or raw.get("content")) else ""
    if not block_type:
        return None
    if block_type == "table":
        return _normalise_table(raw, index, used)

    block_id = _unique_id("b", used, raw.get("id") or f"{block_type}-{index + 1}")
    if block_type == "heading":
        text = clean_text(raw.get("text") or raw.get("heading"), 1000)
        if not text:
            return None
        return {
            "id": block_id,
            "type": "heading",
            "level": _as_int(raw.get("level"), 1, 1, 3),
            "text": text,
        }
    if block_type == "paragraph":
        text = clean_text(raw.get("text") or raw.get("content"))
        if not text:
            return None
        return {"id": block_id, "type": "paragraph", "text": text}
    if block_type == "list":
        items = [clean_text(item, 2000) for item in _as_list(raw.get("items"))]
        if not items and (raw.get("text") or raw.get("content")):
            items = [clean_text(line, 2000) for line in clean_text(raw.get("text") or raw.get("content")).splitlines() if line.strip()]
        if not items:
            return None
        if any(re.search(r"(?:->|→|=>|➜|➡)", item) for item in items):
            return {
                "id": block_id,
                "type": "flow",
                "title": clean_text(raw.get("title"), 500),
                "steps": [{"label": "", "text": item} for item in items[:12]],
            }
        return {
            "id": block_id,
            "type": "list",
            "ordered": bool(raw.get("ordered", False)),
            "items": items[:200],
        }
    if block_type == "callout":
        text = clean_text(raw.get("text") or raw.get("content"))
        label = clean_text(raw.get("label") or raw.get("title"), 200)
        if not text and not label:
            return None
        return {"id": block_id, "type": "callout", "label": label, "text": text}
    if block_type == "question":
        question = clean_text(raw.get("question") or raw.get("text") or raw.get("content"))
        answer = clean_text(raw.get("answer"))
        if not question and not answer:
            return None
        return {"id": block_id, "type": "question", "question": question, "answer": answer}
    if block_type == "formula":
        text = clean_text(raw.get("text") or raw.get("latex") or raw.get("content"))
        if not text:
            return None
        return {"id": block_id, "type": "formula", "text": text}
    if block_type == "flow":
        steps = []
        for step in _as_list(raw.get("steps") or raw.get("items")):
            if isinstance(step, dict):
                label = clean_text(step.get("label"), 200)
                text = clean_text(step.get("text") or step.get("label"), 500)
                if text:
                    steps.append({"label": label, "text": text})
            else:
                text = clean_text(step, 500)
                if text:
                    steps.append({"label": "", "text": text})
        if not steps:
            return None
        return {
            "id": block_id,
            "type": "flow",
            "title": clean_text(raw.get("title"), 500),
            "steps": steps[:12],
        }
    if block_type == "diagram":
        diagram_id = clean_text(raw.get("diagram_id") or raw.get("diagramId"), 80)
        if not diagram_id:
            return None
        return {"id": block_id, "type": "diagram", "diagram_id": diagram_id}
    if block_type == "uncertain":
        text = clean_text(raw.get("text") or raw.get("content"))
        if not text:
            return None
        return {
            "id": block_id,
            "type": "uncertain",
            "text": text,
            "reason": clean_text(raw.get("reason"), 500),
        }
    if block_type == "page_break":
        return {"id": block_id, "type": "page_break"}
    return None


def _normalise_bbox(value: Any) -> list[float]:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return [0.0, 0.0, 0.0, 0.0]
    result = []
    for item in value:
        try:
            number = float(item)
        except (TypeError, ValueError):
            number = 0.0
        if number <= 1.0:
            number *= 1000.0
        result.append(max(0.0, min(1000.0, number)))
    return result


def _normalise_points(value: Any) -> list[float]:
    """Accept both flat [x,y,...] and paired [[x,y],...] point lists."""
    if not isinstance(value, (list, tuple)):
        return []
    result: list[float] = []
    paired = bool(value) and all(isinstance(item, (list, tuple)) for item in value)
    if paired:
        for pair in value[:MAX_SCENE_ELEMENTS]:
            if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                continue
            try:
                result.extend([float(pair[0]), float(pair[1])])
            except (TypeError, ValueError):
                continue
    else:
        for item in value[:MAX_SCENE_ELEMENTS * 2]:
            try:
                result.append(float(item))
            except (TypeError, ValueError):
                continue
    return [max(0.0, min(4000.0, number)) for number in result[:MAX_SCENE_ELEMENTS * 2]]


def _normalise_scene(scene: Any) -> dict:
    if not isinstance(scene, dict):
        return {}
    canvas = scene.get("canvas") or [1000, 700]
    try:
        width = max(100, min(4000, float(canvas[0])))
        height = max(100, min(4000, float(canvas[1])))
    except (TypeError, ValueError, IndexError):
        width, height = 1000, 700
    elements = []
    for raw in _as_list(scene.get("elements"))[:MAX_SCENE_ELEMENTS]:
        if not isinstance(raw, dict):
            continue
        kind = clean_text(raw.get("kind"), 40).lower()
        if kind not in {"shape", "connector", "text"}:
            continue
        shape = clean_text(raw.get("shape"), 40).lower()
        shape = {
            "rectangle": "rect", "rounded_rect": "rect", "roundrect": "rect",
            "oval": "ellipse", "diamond": "diamond", "triangle": "triangle",
        }.get(shape, shape)
        item = {
            "id": clean_text(raw.get("id"), 80),
            "kind": kind,
            "shape": shape,
            "bbox": _normalise_bbox(raw.get("bbox")),
            "points": _normalise_points(raw.get("points")),
            "d": clean_text(raw.get("d"), 12000),
            "from": clean_text(raw.get("from"), 80),
            "to": clean_text(raw.get("to"), 80),
            "arrow": clean_text(raw.get("arrow"), 20).lower(),
            "label": clean_text(raw.get("label"), 1000),
            "text": clean_text(raw.get("text"), 2000),
            "x": raw.get("x"),
            "y": raw.get("y"),
            "style": raw.get("style") if isinstance(raw.get("style"), dict) else {},
        }
        if kind == "connector" and not (item["from"] and item["to"]) and not item["points"]:
            continue
        if kind == "shape" and item["shape"] not in {
            "rect", "circle", "ellipse", "line", "polyline", "polygon", "path",
            "arrow", "diamond", "triangle"
        }:
            continue
        elements.append(item)
    return {"canvas": [width, height], "elements": elements}


def _clean_warning_text(value):
    text = clean_text(value, 500)
    replacements = {
        "No safe vector specification was returned for this diagram.":
            "The source diagram is preserved for accuracy because a reliable vector structure was not available.",
        "Only labels were detected. The original diagram crop will be preserved so no incorrect structure is invented.":
            "Labels were identified, but the visible structure was incomplete. The source crop is used so no incorrect structure is invented.",
        "The original diagram crop will be preserved because no safe vector structure was returned.":
            "The source diagram is preserved because a reliable vector structure was not returned.",
        "This diagram has labels but no safe vector structure. The original diagram crop will be preserved instead.":
            "The source diagram is used for accuracy because a reliable vector structure is not available.",
    }
    return replacements.get(text, text)


def _normalise_quality(raw: Any) -> dict:
    """Keep a small, JSON-safe structural-quality report."""
    if not isinstance(raw, dict):
        return {}
    quality: dict = {}
    for key in ("method", "reason"):
        text = clean_text(raw.get(key), 300)
        if text:
            quality[key] = text
    for key in (
        "structural_match",
        "light_fraction",
        "dark_fraction",
        "ink_fraction",
        "background_fraction",
        "mean_chroma",
    ):
        try:
            quality[key] = round(float(raw.get(key)), 4)
        except (TypeError, ValueError):
            continue
    for key in ("threshold", "width", "height", "contours", "points", "path_chars"):
        try:
            quality[key] = int(float(raw.get(key)))
        except (TypeError, ValueError):
            continue
    for key in ("line_art", "accepted"):
        if isinstance(raw.get(key), bool):
            quality[key] = raw[key]
    return quality


def _normalise_diagram(raw: Any, index: int, page_index: int, used: set[str]) -> dict | None:
    if not isinstance(raw, dict):
        return None
    diagram_id = _unique_id("d", used, raw.get("id") or f"diagram-{index + 1}")
    diagram_type = clean_text(raw.get("type"), 100).lower()
    category = clean_text(raw.get("category"), 40).lower()
    if category not in _DIAGRAM_CATEGORIES:
        category = "other"
    template_data = raw.get("template_data") if isinstance(raw.get("template_data"), dict) else {}
    scene = _normalise_scene(raw.get("scene"))
    labels = []
    for label in _as_list(raw.get("labels")):
        if isinstance(label, dict):
            text = clean_text(label.get("text") or label.get("label"), 500)
            source = clean_text(label.get("source_text") or label.get("source"), 500)
            if text:
                labels.append({"text": text, "source_text": source, "confidence": _as_float(label.get("confidence"), 1.0)})
        else:
            text = clean_text(label, 500)
            if text:
                labels.append({"text": text, "source_text": text, "confidence": 1.0})

    uncertain = [clean_text(item, 500) for item in _as_list(raw.get("uncertain")) if clean_text(item, 500)]
    review_required = bool(raw.get("review_required", False)) or bool(uncertain)
    warnings: list[str] = [
        _clean_warning_text(item)
        for item in _as_list(raw.get("warnings"))
        if clean_text(item, 500)
    ]
    corrections: list[dict] = []

    if diagram_type == "solar_system":
        planets_raw = template_data.get("planets") or []
        planets = []
        for planet in planets_raw:
            name = planet.get("name") if isinstance(planet, dict) else planet
            canonical, corrected = canonical_planet_name(name)
            if not canonical:
                continue
            if corrected:
                corrections.append({"from": clean_text(name, 80), "to": canonical})
            if canonical not in {p["name"] for p in planets}:
                planets.append({"name": canonical, "order": len(planets) + 1})
        names = {p["name"] for p in planets}
        if names == set(PLANETS):
            planets = [{"name": name, "order": order + 1} for order, name in enumerate(PLANETS)]
            template_data = dict(template_data)
            template_data["planets"] = planets
        else:
            review_required = True
            missing = [name for name in PLANETS if name not in names]
            extra = sorted(names - set(PLANETS))
            if missing:
                warnings.append("Solar System diagram is missing: " + ", ".join(missing))
            if extra:
                warnings.append("Solar System diagram has unrecognised labels: " + ", ".join(extra))
        if corrections:
            warnings.append("Corrected clear planet spelling: " + ", ".join(f"{c['from']} → {c['to']}" for c in corrections))

    if diagram_type == "chart":
        chart_type = clean_text(template_data.get("chart_type") or template_data.get("type"), 20).lower()
        if chart_type not in {"bar", "line", "pie"}:
            chart_type = "bar"
        labels = [clean_text(item, 100) for item in _as_list(template_data.get("labels")) if clean_text(item, 100)]
        raw_values = _as_list(template_data.get("values"))
        values = []
        for value in raw_values:
            try:
                values.append(float(value))
            except (TypeError, ValueError):
                values.append(None)
        if not values or any(value is None for value in values):
            review_required = True
            warnings.append("Chart data is incomplete or unclear; verify values before trusting this chart.")
        if labels and values and not any(value is None for value in values):
            template_data = dict(template_data)
            template_data["chart_type"] = chart_type
            template_data["labels"] = labels[:60]
            template_data["values"] = values[:60]
        elif values:
            review_required = True
            warnings.append("Chart category labels or numeric values are incomplete; original crop may be safer.")
        else:
            review_required = True
            warnings.append("Chart values are missing; original crop may be safer.")

    # A model sometimes labels a highlighted text box or memory-trick card as
    # a diagram while returning no shapes, labels or template data. That is not
    # a diagram; dropping it avoids an unnecessary raster crop and keeps the
    # actual text in its callout/paragraph block.
    diagram_title = clean_text(raw.get("title"), 500)
    if (
        not template_data
        and not scene.get("elements")
        and re.search(r"\b(memory|trick|callout|summary|list)\b", diagram_title, re.IGNORECASE)
    ):
        return None

    source_preview = (
        clean_text(raw.get("source_preview"), 500000)
        if str(raw.get("source_preview") or "").startswith("data:image/")
        else ""
    )
    recreation_mode = clean_text(raw.get("recreation_mode"), 20).lower()
    if recreation_mode not in {"trace", "ai"}:
        recreation_mode = ""
    if recreation_mode == "trace" and not source_preview:
        recreation_mode = ""
    has_trace = recreation_mode == "trace" and bool(source_preview)

    can_synthesize_flow = diagram_type == "flowchart" and len(labels) >= 2
    safe_vector_missing = (
        not template_data
        and not scene.get("elements")
        and not can_synthesize_flow
        and not has_trace
    )
    if (
        not template_data
        and not scene.get("elements")
        and not can_synthesize_flow
        and not has_trace
    ):
        review_required = True
        warnings.append("The source diagram is preserved for accuracy because a reliable vector structure was not available.")
        if labels:
            warnings.append(
                "Labels were identified, but the visible structure was incomplete. The source crop is used so no incorrect structure is invented."
            )
        else:
            warnings.append(
                "The source diagram is preserved because a reliable vector structure was not returned."
            )

    warnings = list(dict.fromkeys(warnings))
    uncertain = list(dict.fromkeys(uncertain))
    placement = raw.get("placement") if isinstance(raw.get("placement"), dict) else {}
    return {
        "id": diagram_id,
        "page_index": page_index,
        "category": category,
        "type": diagram_type or "unknown",
        "title": clean_text(raw.get("title"), 500),
        "confidence": _as_float(raw.get("confidence"), 0.0),
        "placement": {
            "anchor_block_id": clean_text(placement.get("anchor_block_id"), 80),
            "position": clean_text(placement.get("position"), 20).lower() or "after",
        },
        "source_bbox": _normalise_bbox(raw.get("source_bbox")),
        "labels": labels[:200],
        "template_data": template_data,
        "scene": scene,
        "uncertain": uncertain[:50],
        "review_required": review_required,
        "warnings": warnings,
        "corrections": corrections,
        "source_preview": source_preview,
        "recreation_mode": recreation_mode,
        "quality": _normalise_quality(raw.get("quality")),
        # A label-only diagram has no safe geometry. Keep the source crop
        # automatically instead of asking the renderer for an impossible SVG.
        "use_original": (
            (safe_vector_missing and not has_trace)
            or bool(raw.get("use_original", False))
        ),
        "excluded": bool(raw.get("excluded", False)),
    }


_LIST_ITEM_RE = re.compile(r"^(?:[•\-*·]|\d+[.)]|[a-zA-Z][.)])\s+(.+)$")
_CALLOUT_RE = re.compile(
    r"^(trick|remember|note|shortcut|golden rule|important|tip|warning|total|practice daily)\b"
    r"\s*[:\-–—]?\s*(.*)$",
    re.IGNORECASE,
)
_QA_RE = re.compile(r"^(?:q(?:uestion)?)\s*[:\-.)]\s*(.+)$", re.IGNORECASE)
_ANSWER_RE = re.compile(r"^(?:a(?:nswer)?)\s*[:\-.)]\s*(.+)$", re.IGNORECASE)
_KEY_VALUE_RE = re.compile(r"^([^:|]{1,50}?)\s*:\s*(.+)$")
_ARROW_RE = re.compile(r"\s*(?:->|→|=>|➜|➡)\s*")
_FORMULA_TOKEN_RE = re.compile(
    r"(?:^|\s)(?:V\d|Ving|V3|Verb|Subject|S\s*\+|am/is/are|was/were|will\b|has/have|had\b)",
    re.IGNORECASE,
)


def _new_block(used: set[str], preferred: str, **fields) -> dict:
    return {"id": _unique_id("b", used, preferred), **fields}


def _looks_like_formula(line: str) -> bool:
    text = clean_text(line, 2000)
    if not text or len(text) > 300:
        return False
    if "=" in text:
        return True
    return bool(_FORMULA_TOKEN_RE.search(text) and ("+" in text or "V" in text))


def _parse_key_value_chart(lines: list[str], heading: str) -> tuple[list[str], list[list[str]]] | None:
    """Turn Present/Past/Future style colon lines into a real three-column chart."""
    pairs: list[tuple[str, str]] = []
    for line in lines:
        match = _KEY_VALUE_RE.match(line)
        if not match:
            return None
        key, value = match.group(1).strip(), match.group(2).strip()
        if not key or not value or _ARROW_RE.search(value):
            return None
        pairs.append((key, value))
    if len(pairs) < 2:
        return None
    keys = [key for key, _value in pairs]
    lowered = {key.casefold() for key in keys}
    is_helping_chart = (
        {"present", "past", "future"}.issubset(lowered)
        or "helping" in heading.casefold()
        or "chart" in heading.casefold()
        or "comparison" in heading.casefold()
    )
    if not is_helping_chart:
        return None
    values = []
    for _key, value in pairs:
        parts = [part.strip() for part in re.split(r"[,;]", value) if part.strip()]
        values.append(parts or [value])
    row_count = max(len(items) for items in values)
    rows = [
        [values[column][row] if row < len(values[column]) else "" for column in range(len(keys))]
        for row in range(row_count)
    ]
    return keys, rows


def _parse_flow_blocks(lines: list[str]) -> list[dict]:
    """Parse arrow lines such as 'Present: Do -> Doing -> Done'."""
    flows: list[dict] = []
    for line in lines:
        match = _KEY_VALUE_RE.match(line)
        if match:
            label, body = match.group(1).strip(), match.group(2).strip()
        else:
            label, body = "", line.strip()
        if not _ARROW_RE.search(body):
            return []
        steps = [part.strip() for part in _ARROW_RE.split(body) if part.strip()]
        if len(steps) < 2:
            return []
        flows.append({
            "type": "flow",
            "title": label,
            "steps": [{"label": "", "text": step} for step in steps],
        })
    return flows


def _content_to_blocks(content: str, heading: str, used: set[str]) -> list[dict]:
    """Convert legacy section text into typed blocks without losing content.

    Legacy extraction returned one long ``content`` string per section. The
    professional PDF used to print that string as a paragraph, which is why
    pipe tables appeared as fake text tables. This parser recognises tables,
    key/value charts, callouts, lists, Q&A pairs, formulas and arrow flows.
    """
    lines = [line.strip() for line in clean_text(content).splitlines()]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return []

    heading_lower = heading.casefold()
    # A memory-trick section is a visual card, not a paragraph. Keep its lines
    # together so the highlighted card preserves the original grouping.
    if (
        len(lines) > 1
        and ("memory" in heading_lower or "trick" in heading_lower)
        and not any("|" in line for line in lines)
        and not all(_ARROW_RE.search(line) for line in lines)
        and not _parse_key_value_chart(lines, heading)
    ):
        return [_new_block(
            used, "callout-memory",
            type="callout",
            label="Memory Trick" if "memory" in heading_lower else "Trick",
            text="\n".join(lines),
        )]

    # A complete arrow sequence is a flow, not a paragraph.
    if all(_ARROW_RE.search(line) for line in lines):
        flows = _parse_flow_blocks(lines)
        if flows:
            return [
                _new_block(used, f"flow-{index + 1}", **flow)
                for index, flow in enumerate(flows)
            ]

    blocks: list[dict] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line:
            index += 1
            continue

        # Pipe table segment. Only contiguous pipe lines belong to the table;
        # trailing tips stay separate callouts.
        if "|" in line:
            segment = []
            while index < len(lines) and lines[index] and "|" in lines[index]:
                segment.append(lines[index])
                index += 1
            columns, rows = _parse_pipe_table("\n".join(segment))
            if columns and (rows or len(segment) > 1):
                # A model may put a few trailing chart values on bullet lines
                # instead of pipe rows. Merge them into a Present/Past/Future
                # chart rather than leaving an orphan list below it.
                if [column.casefold() for column in columns] == ["present", "past", "future"]:
                    while index < len(lines):
                        match = _LIST_ITEM_RE.match(lines[index])
                        if not match:
                            break
                        rows.append([match.group(1).strip(), "", ""])
                        index += 1
                blocks.append(_new_block(
                    used, f"table-{len(blocks) + 1}",
                    type="table",
                    title="",
                    columns=columns[:20],
                    rows=rows[:200],
                    header=True,
                    align=[],
                ))
            elif columns:
                # One pipe-separated line is usually a formula, not a table
                # header with zero rows.
                single = re.sub(r"\s*\|\s*", "    ", segment[0]).strip()
                if _looks_like_formula(single):
                    blocks.append(_new_block(
                        used, f"formula-{len(blocks) + 1}",
                        type="formula",
                        text=single,
                    ))
                else:
                    blocks.append(_new_block(
                        used, f"paragraph-{len(blocks) + 1}",
                        type="paragraph",
                        text=single,
                    ))
            else:
                blocks.append(_new_block(
                    used, f"paragraph-{len(blocks) + 1}",
                    type="paragraph",
                    text="\n".join(segment),
                ))
            continue

        qa = _QA_RE.match(line)
        if qa:
            question = qa.group(1).strip()
            answer = ""
            if index + 1 < len(lines):
                answer_match = _ANSWER_RE.match(lines[index + 1])
                if answer_match:
                    answer = answer_match.group(1).strip()
                    index += 1
            blocks.append(_new_block(
                used, f"question-{len(blocks) + 1}",
                type="question",
                question=question,
                answer=answer,
            ))
            index += 1
            continue

        callout = _CALLOUT_RE.match(line)
        if callout:
            label = callout.group(1).strip().title()
            parts = [callout.group(2).strip()] if callout.group(2).strip() else []
            index += 1
            while index < len(lines) and lines[index]:
                candidate = lines[index]
                if (
                    "|" in candidate
                    or _LIST_ITEM_RE.match(candidate)
                    or _QA_RE.match(candidate)
                    or _CALLOUT_RE.match(candidate)
                ):
                    break
                parts.append(candidate)
                index += 1
            blocks.append(_new_block(
                used, f"callout-{len(blocks) + 1}",
                type="callout",
                label=label,
                text="\n".join(parts).strip(),
            ))
            continue

        list_match = _LIST_ITEM_RE.match(line)
        if list_match:
            ordered = bool(re.match(r"^\d+[.)]\s+", line))
            items = []
            while index < len(lines):
                match = _LIST_ITEM_RE.match(lines[index])
                if not match:
                    break
                items.append(match.group(1).strip())
                index += 1
            if "formula" in heading_lower and items and all(_looks_like_formula(item) for item in items):
                blocks.append(_new_block(
                    used, f"formula-{len(blocks) + 1}",
                    type="formula",
                    text="\n".join(items),
                ))
            else:
                blocks.append(_new_block(
                    used, f"list-{len(blocks) + 1}",
                    type="list",
                    ordered=ordered,
                    items=items[:200],
                ))
            continue

        # Key/value blocks are often charts (Present/Past/Future) or formulas
        # (Simple: Subject + Verb). Recognise them before generic paragraphs.
        key_lines = []
        cursor = index
        while cursor < len(lines) and lines[cursor] and "|" not in lines[cursor]:
            if not _KEY_VALUE_RE.match(lines[cursor]):
                break
            key_lines.append(lines[cursor])
            cursor += 1
        if len(key_lines) >= 2:
            if any(_ARROW_RE.search(item) for item in key_lines):
                flows = _parse_flow_blocks(key_lines)
                if flows:
                    blocks.extend(
                        _new_block(used, f"flow-{len(blocks) + 1}", **flow)
                        for flow in flows
                    )
                    index = cursor
                    continue
            chart = _parse_key_value_chart(key_lines, heading)
            if chart:
                columns, rows = chart
                blocks.append(_new_block(
                    used, f"table-{len(blocks) + 1}",
                    type="table",
                    title="",
                    columns=columns[:20],
                    rows=rows[:200],
                    header=True,
                    align=[],
                ))
                index = cursor
                continue
            if (
                any(token in heading_lower for token in ("formula", "master", "structure"))
                or all(_looks_like_formula(item) for item in key_lines)
            ):
                blocks.append(_new_block(
                    used, f"formula-{len(blocks) + 1}",
                    type="formula",
                    text="\n".join(key_lines),
                ))
                index = cursor
                continue

        if _ARROW_RE.search(line):
            flows = _parse_flow_blocks([line])
            if flows:
                blocks.extend(
                    _new_block(used, f"flow-{len(blocks) + 1}", **flow)
                    for flow in flows
                )
                index += 1
                continue

        if _looks_like_formula(line):
            formula_lines = [line]
            index += 1
            while index < len(lines) and lines[index] and _looks_like_formula(lines[index]):
                if _LIST_ITEM_RE.match(lines[index]) or _CALLOUT_RE.match(lines[index]):
                    break
                formula_lines.append(lines[index])
                index += 1
            blocks.append(_new_block(
                used, f"formula-{len(blocks) + 1}",
                type="formula",
                text="\n".join(formula_lines),
            ))
            continue

        paragraph = [line]
        index += 1
        while index < len(lines) and lines[index]:
            candidate = lines[index]
            if (
                "|" in candidate
                or _LIST_ITEM_RE.match(candidate)
                or _QA_RE.match(candidate)
                or _CALLOUT_RE.match(candidate)
                or _ARROW_RE.search(candidate)
                or _looks_like_formula(candidate)
            ):
                break
            paragraph.append(candidate)
            index += 1
        blocks.append(_new_block(
            used, f"paragraph-{len(blocks) + 1}",
            type="paragraph",
            text="\n".join(paragraph),
        ))
    return blocks


def _sections_to_blocks(data: dict, used: set[str]) -> list[dict]:
    blocks: list[dict] = []
    title = clean_text(data.get("title"), 1000)
    if title:
        blocks.append({"id": _unique_id("b", used, "title"), "type": "heading", "level": 1, "text": title})
    for section in _as_list(data.get("sections")):
        if not isinstance(section, dict):
            continue
        heading = clean_text(section.get("heading"), 1000)
        content = clean_text(section.get("content"))
        # A standalone "Practice Daily + Understand + Use = Master" line is a
        # highlighted takeaway, not an empty heading.
        if heading and not content and "=" in heading:
            blocks.append(_new_block(
                used, f"callout-{len(blocks) + 1}",
                type="callout",
                label="Practice",
                text=heading,
            ))
            continue
        if heading:
            blocks.append({
                "id": _unique_id("b", used, f"heading-{len(blocks) + 1}"),
                "type": "heading",
                "level": _as_int(section.get("level"), 1, 1, 3),
                "text": heading,
            })
        if content:
            blocks.extend(_content_to_blocks(content, heading, used))
    return blocks


def _normalise_page(raw: dict, page_index: int) -> dict:
    used_blocks: set[str] = set()
    used_diagrams: set[str] = set()
    blocks_raw = raw.get("blocks")
    if isinstance(blocks_raw, list):
        blocks = [block for block in (_normalise_block(item, index, used_blocks) for index, item in enumerate(blocks_raw[:MAX_BLOCKS_PER_PAGE])) if block]
    else:
        blocks = _sections_to_blocks(raw, used_blocks)

    raw_diagrams = _as_list(raw.get("diagrams"))[:MAX_DIAGRAMS_PER_PAGE]
    diagrams = [
        diagram for diagram in (
            _normalise_diagram(item, index, page_index, used_diagrams)
            for index, item in enumerate(raw_diagrams)
        ) if diagram
    ]

    diagram_ids = {diagram["id"] for diagram in diagrams}
    filtered_blocks = []
    for block in blocks:
        if block.get("type") != "diagram" or block.get("diagram_id") in diagram_ids:
            filtered_blocks.append(block)
            continue
        # A text-layout "diagram" was discarded as non-pictorial. Preserve its
        # visible labels as a callout instead of silently losing the content.
        raw_diagram = next(
            (item for item in raw_diagrams
             if isinstance(item, dict) and str(item.get("id") or "") == str(block.get("diagram_id") or "")),
            None,
        )
        if not raw_diagram:
            continue
        title = clean_text(raw_diagram.get("title"), 500)
        if not re.search(r"\b(memory|trick|callout|summary|list)\b", title, re.IGNORECASE):
            continue
        labels = []
        for label in _as_list(raw_diagram.get("labels")):
            text = clean_text(label.get("text") if isinstance(label, dict) else label, 500)
            if text and text not in labels:
                labels.append(text)
        if labels:
            filtered_blocks.append({
                "id": _unique_id("b", used_blocks, f"callout-{block.get('diagram_id')}"),
                "type": "callout",
                "label": "Memory Trick" if "memory" in title.casefold() else "Trick",
                "text": "\n".join(labels),
            })
    blocks = filtered_blocks
    referenced = {block.get("diagram_id") for block in blocks if block.get("type") == "diagram"}
    for diagram in diagrams:
        if diagram["id"] in referenced:
            continue
        anchor = diagram.get("placement", {}).get("anchor_block_id") or ""
        insert_at = len(blocks)
        if anchor:
            for index, block in enumerate(blocks):
                if block.get("id") == anchor:
                    insert_at = index + (1 if diagram.get("placement", {}).get("position") != "before" else 0)
                    break
        else:
            # Never append at the end when a heading exists: place after the
            # nearest heading so a diagram keeps its related section.
            for index, block in enumerate(blocks):
                if block.get("type") == "heading":
                    insert_at = index + 1
                    break
        blocks.insert(insert_at, {
            "id": _unique_id("b", used_blocks, f"diagram-block-{diagram['id']}"),
            "type": "diagram",
            "diagram_id": diagram["id"],
        })

    # Enforce the model's own placement anchor. Some models put the diagram
    # block at the end of the page even when they correctly return an anchor;
    # this keeps the diagram next to its related heading/explanation.
    for diagram in diagrams:
        anchor_id = diagram.get("placement", {}).get("anchor_block_id") or ""
        if not anchor_id:
            continue
        diagram_index = next(
            (index for index, block in enumerate(blocks)
             if block.get("type") == "diagram" and block.get("diagram_id") == diagram["id"]),
            None,
        )
        anchor_index = next(
            (index for index, block in enumerate(blocks) if block.get("id") == anchor_id),
            None,
        )
        if diagram_index is None or anchor_index is None:
            continue
        position = diagram.get("placement", {}).get("position") or "after"
        desired = anchor_index + (1 if position != "before" else 0)
        if diagram_index == desired:
            continue
        block = blocks.pop(diagram_index)
        anchor_index = next(
            (index for index, item in enumerate(blocks) if item.get("id") == anchor_id),
            None,
        )
        if anchor_index is None:
            blocks.append(block)
            continue
        desired = anchor_index + (1 if position != "before" else 0)
        blocks.insert(desired, block)

    return {
        "page_index": page_index,
        "title": clean_text(raw.get("title"), 1000),
        "subtitle": clean_text(raw.get("subtitle"), 1000),
        "blocks": blocks[:MAX_BLOCKS_PER_PAGE],
        "diagrams": diagrams,
        "warnings": [_clean_warning_text(item) for item in _as_list(raw.get("warnings")) if clean_text(item, 500)],
    }


def normalise_analysis(data: Any, page_index: int = 0) -> dict:
    """Return a stable schema-v2 document, accepting legacy title/sections JSON."""
    if not isinstance(data, dict):
        data = {}
    if isinstance(data.get("pages"), list) and data["pages"]:
        pages = [
            _normalise_page(page, _as_int(page.get("page_index"), index, 0, 999))
            for index, page in enumerate(data["pages"][:24])
            if isinstance(page, dict)
        ]
        title = clean_text(data.get("title"), 1000) or next((page["title"] for page in pages if page["title"]), "")
        subtitle = clean_text(data.get("subtitle"), 1000) or next((page["subtitle"] for page in pages if page["subtitle"]), "")
    else:
        page = _normalise_page(data, page_index)
        pages = [page]
        title = page["title"]
        subtitle = page["subtitle"]

    warnings: list[str] = []
    for page in pages:
        warnings.extend(page.get("warnings", []))
        for diagram in page.get("diagrams", []):
            warnings.extend(diagram.get("warnings", []))
    # Keep a single title and avoid repeating it as the first heading.
    title_key = re.sub(r"\s+", " ", title).strip().casefold()
    if title_key:
        for page in pages:
            page_blocks = []
            for block in page["blocks"]:
                if block.get("type") == "heading" and re.sub(r"\s+", " ", block.get("text", "")).strip().casefold() == title_key:
                    continue
                page_blocks.append(block)
            page["blocks"] = page_blocks

    return {
        "schema_version": SCHEMA_VERSION,
        "title": title or "Converted Document",
        "subtitle": subtitle,
        "pages": pages,
        "warnings": warnings[:100],
    }


def _block_to_markdown(block: dict) -> str:
    block_type = block.get("type")
    if block_type == "heading":
        return ("#" * max(1, min(3, int(block.get("level", 1))))) + " " + block.get("text", "")
    if block_type == "paragraph":
        return block.get("text", "")
    if block_type == "list":
        items = block.get("items") or []
        marker = "1." if block.get("ordered") else "-"
        return "\n".join(f"{marker} {item}" for item in items)
    if block_type == "table":
        columns = block.get("columns") or []
        rows = block.get("rows") or []
        lines = []
        if columns:
            lines.append("| " + " | ".join(columns) + " |")
            lines.append("| " + " | ".join("---" for _ in columns) + " |")
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines)
    if block_type == "callout":
        label = block.get("label") or "Note"
        return f"**{label}:** {block.get('text', '')}"
    if block_type == "question":
        return f"Q: {block.get('question', '')}\nA: {block.get('answer', '')}"
    if block_type == "formula":
        return block.get("text", "")
    if block_type == "flow":
        title = block.get("title") or ""
        steps = " → ".join(str(step.get("text", "")) for step in block.get("steps") or [] if isinstance(step, dict))
        return f"{title}: {steps}" if title else steps
    if block_type == "diagram":
        return f"[Diagram: {block.get('diagram_id', '')}]"
    if block_type == "uncertain":
        return f"[Unclear: {block.get('text', '')}]"
    return ""


def analysis_to_text(analysis: dict) -> str:
    analysis = normalise_analysis(analysis)
    chunks: list[str] = []
    if analysis.get("title"):
        chunks.append("# " + analysis["title"])
    if analysis.get("subtitle"):
        chunks.append(analysis["subtitle"])
    for page in analysis.get("pages", []):
        if len(analysis.get("pages", [])) > 1:
            chunks.append(f"## Page {page.get('page_index', 0) + 1}")
        for block in page.get("blocks", []):
            text = _block_to_markdown(block).strip()
            if text:
                chunks.append(text)
    return "\n\n".join(chunks).strip()


def analysis_to_structured(analysis: dict) -> dict:
    analysis = normalise_analysis(analysis)
    sections: list[dict] = []
    current = {"heading": "", "level": 1, "content": ""}
    for page in analysis.get("pages", []):
        for block in page.get("blocks", []):
            block_type = block.get("type")
            if block_type == "heading":
                if current["heading"] or current["content"].strip():
                    sections.append(current)
                current = {"heading": block.get("text", ""), "level": block.get("level", 1), "content": ""}
            elif block_type == "paragraph":
                current["content"] = (current["content"] + "\n\n" + block.get("text", "")).strip()
            elif block_type == "list":
                items = "\n".join(("- " if not block.get("ordered") else f"{i + 1}. ") + str(item) for i, item in enumerate(block.get("items") or []))
                current["content"] = (current["content"] + "\n\n" + items).strip()
            elif block_type == "table":
                columns = block.get("columns") or []
                rows = block.get("rows") or []
                table = " | ".join(columns) + "\n" + "\n".join(" | ".join(row) for row in rows)
                current["content"] = (current["content"] + "\n\n" + table).strip()
            elif block_type == "callout":
                current["content"] = (current["content"] + f"\n\n**{block.get('label') or 'Note'}:** {block.get('text', '')}").strip()
            elif block_type == "question":
                current["content"] = (current["content"] + f"\n\nQ: {block.get('question', '')}\nA: {block.get('answer', '')}").strip()
            elif block_type == "formula":
                current["content"] = (current["content"] + "\n\n" + block.get("text", "")).strip()
            elif block_type == "flow":
                steps = " → ".join(str(step.get("text", "")) for step in block.get("steps") or [] if isinstance(step, dict))
                title = block.get("title") or ""
                flow_text = f"{title}: {steps}" if title else steps
                current["content"] = (current["content"] + "\n\n" + flow_text).strip()
            elif block_type == "diagram":
                diagram = next((d for d in page.get("diagrams", []) if d.get("id") == block.get("diagram_id")), None)
                label = diagram.get("title") if diagram else block.get("diagram_id")
                current["content"] = (current["content"] + f"\n\n[Diagram: {label}]").strip()
            elif block_type == "uncertain":
                current["content"] = (current["content"] + f"\n\n[Unclear: {block.get('text', '')}]").strip()
    if current["heading"] or current["content"].strip():
        sections.append(current)
    return {"title": analysis.get("title", ""), "subtitle": analysis.get("subtitle", ""), "sections": sections}


def normalise_diagram(raw: Any, page_index: int = 0) -> dict | None:
    """Public single-diagram normaliser used by preview/regenerate endpoints."""
    return _normalise_diagram(raw, 0, page_index, set())


def iter_diagrams(analysis: dict, normalise: bool = True) -> list[dict]:
    if normalise:
        analysis = normalise_analysis(analysis)
    return [diagram for page in analysis.get("pages", []) for diagram in page.get("diagrams", [])]


def analysis_has_arabic(analysis: dict) -> bool:
    text = analysis_to_text(analysis)
    return bool(re.search(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]", text))
