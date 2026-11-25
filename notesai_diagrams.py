"""Deterministic SVG diagram renderers for NotesAI.

The AI is only allowed to return a structured specification. This module turns
that specification into safe, local SVG. No model-generated SVG or external
image-generation service is used. If a specification cannot be rendered, the
PDF layer can preserve the original diagram crop instead.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable
from xml.sax.saxutils import escape

from notesai_schema import PLANETS, clean_text, normalise_diagram

try:
    from notesai_trace import TraceQualityError, trace_data_url
except Exception:  # pragma: no cover - defensive, trace module is always present
    trace_data_url = None  # type: ignore

    class TraceQualityError(RuntimeError):
        pass


class DiagramRenderError(RuntimeError):
    pass


_RENDERERS: dict[str, Callable[[dict], str]] = {}
_ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]")
_DIAGRAM_STYLES = {
    "color", "pencil", "3d", "simple",
    "medical", "vector", "schematic", "molecule2d", "structure3d",
    "outline", "topographic",
}


def normalise_diagram_style(value: Any) -> str:
    style = str(value or "color").strip().lower()
    return style if style in _DIAGRAM_STYLES else "color"

# Conservative educational palette.
_INK = "#0f172a"
_MUTED = "#64748b"
_BLUE = "#1e3a8a"
_BLUE_2 = "#3b82f6"
_LINE = "#94a3b8"
_PALE = "#e2e8f0"


def register(name: str):
    def decorator(fn: Callable[[dict], str]):
        _RENDERERS[name] = fn
        return fn
    return decorator


def _x(value: Any) -> str:
    return escape(str(value), {'"': "&quot;"})


def _svg(width: float, height: float, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.2f}" height="{height:.2f}" '
        f'viewBox="0 0 {width:.2f} {height:.2f}">'
        f'<rect x="0" y="0" width="{width:.2f}" height="{height:.2f}" fill="#ffffff"/>'
        f'{body}</svg>'
    )


def _text(x: float, y: float, value: Any, size: float = 14, fill: str = _INK,
          anchor: str = "middle", weight: str = "normal", family: str = "sans-serif") -> str:
    return (
        f'<text x="{x:.2f}" y="{y:.2f}" font-family="{_x(family)}" font-size="{size:.2f}" '
        f'font-weight="{_x(weight)}" text-anchor="{_x(anchor)}" fill="{_x(fill)}">{_x(value)}</text>'
    )


def _line(x1: float, y1: float, x2: float, y2: float, color: str = _INK,
          width: float = 1.5, dash: str = "") -> str:
    extra = f' stroke-dasharray="{_x(dash)}"' if dash else ""
    return f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{_x(color)}" stroke-width="{width:.2f}"{extra}/>'


def _arrow(x1: float, y1: float, x2: float, y2: float, color: str = _INK,
           width: float = 1.8, head: float = 10.0) -> str:
    angle = math.atan2(y2 - y1, x2 - x1)
    left = (x2 - head * math.cos(angle - 0.42), y2 - head * math.sin(angle - 0.42))
    right = (x2 - head * math.cos(angle + 0.42), y2 - head * math.sin(angle + 0.42))
    return (
        _line(x1, y1, x2, y2, color, width) +
        f'<polygon points="{x2:.2f},{y2:.2f} {left[0]:.2f},{left[1]:.2f} {right[0]:.2f},{right[1]:.2f}" fill="{_x(color)}"/>'
    )


def _rect(x: float, y: float, w: float, h: float, fill: str = "#ffffff",
          stroke: str = _INK, width: float = 1.5, radius: float = 0) -> str:
    if radius:
        return f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{radius:.2f}" fill="{_x(fill)}" stroke="{_x(stroke)}" stroke-width="{width:.2f}"/>'
    return f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" fill="{_x(fill)}" stroke="{_x(stroke)}" stroke-width="{width:.2f}"/>'


def _circle(cx: float, cy: float, r: float, fill: str = "#ffffff",
            stroke: str = _INK, width: float = 1.5) -> str:
    return f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{_x(fill)}" stroke="{_x(stroke)}" stroke-width="{width:.2f}"/>'


def _ellipse(cx: float, cy: float, rx: float, ry: float, fill: str = "none",
             stroke: str = _INK, width: float = 1.5, rotate: float = 0) -> str:
    transform = f' transform="rotate({rotate:.2f} {cx:.2f} {cy:.2f})"' if rotate else ""
    return f'<ellipse cx="{cx:.2f}" cy="{cy:.2f}" rx="{rx:.2f}" ry="{ry:.2f}" fill="{_x(fill)}" stroke="{_x(stroke)}" stroke-width="{width:.2f}"{transform}/>'


def _bbox(value: Any) -> tuple[float, float, float, float]:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return 0.0, 0.0, 0.0, 0.0
    try:
        x, y, w, h = [float(item) for item in value]
    except (TypeError, ValueError):
        return 0.0, 0.0, 0.0, 0.0
    if w < 0:
        x, w = x + w, -w
    if h < 0:
        y, h = y + h, -h
    return x, y, w, h


def _label_has_arabic(diagram: dict) -> bool:
    texts = [diagram.get("title", "")]
    texts.extend(label.get("text", "") for label in diagram.get("labels", []) if isinstance(label, dict))
    for element in (diagram.get("scene") or {}).get("elements", []):
        if isinstance(element, dict):
            texts.extend([element.get("label", ""), element.get("text", "")])
    return any(_ARABIC_RE.search(str(text or "")) for text in texts)


@register("solar_system")
def render_solar_system(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    raw_planets = data.get("planets") or []
    names = []
    for planet in raw_planets:
        name = planet.get("name") if isinstance(planet, dict) else planet
        if name and str(name).strip() not in names:
            names.append(str(name).strip())
    if set(names) != set(PLANETS):
        raise DiagramRenderError("Solar System needs exactly the eight canonical planets.")
    names = list(PLANETS)

    width, height = 1000.0, 640.0
    sun_x, sun_y = 105.0, 310.0
    body: list[str] = []
    body.append(_text(width / 2, 42, diagram.get("title") or "The Solar System", 26, _BLUE, weight="bold"))
    body.append(_text(width / 2, 66, "Illustrative diagram - not to scale", 12, _MUTED))

    # Orbit paths are half-ellipses so the Sun can stay on the left while the
    # planets remain readable in order from left to right.
    radii = []
    for index in range(8):
        rx = 132.0 + index * 94.0
        ry = 72.0 + index * 21.0
        radii.append((rx, ry))
        body.append(
            f'<path d="M {sun_x:.2f} {sun_y - ry:.2f} A {rx:.2f} {ry:.2f} 0 0 1 {sun_x:.2f} {sun_y + ry:.2f}" '
            f'fill="none" stroke="#cbd5e1" stroke-width="1.15"/>'
        )

    # Sun with a simple layered corona.
    body.append(_circle(sun_x, sun_y, 72, "#fef3c7", "#f59e0b", 2))
    body.append(_circle(sun_x, sun_y, 58, "#fbbf24", "#f59e0b", 2))
    body.append(_circle(sun_x, sun_y, 45, "#fde047", "#f59e0b", 2))
    body.append(_text(sun_x, sun_y + 5, "Sun", 16, "#92400e", weight="bold"))

    styles = {
        "Mercury": {"r": 7.0, "fill": "#9ca3af", "accent": "#6b7280"},
        "Venus": {"r": 10.0, "fill": "#fbbf24", "accent": "#f59e0b"},
        "Earth": {"r": 11.0, "fill": "#60a5fa", "accent": "#22c55e"},
        "Mars": {"r": 9.0, "fill": "#f87171", "accent": "#b91c1c"},
        "Jupiter": {"r": 24.0, "fill": "#fbbf24", "accent": "#b45309"},
        "Saturn": {"r": 20.0, "fill": "#fde68a", "accent": "#b45309"},
        "Uranus": {"r": 14.0, "fill": "#67e8f9", "accent": "#0e7490"},
        "Neptune": {"r": 14.0, "fill": "#60a5fa", "accent": "#1d4ed8"},
    }

    for index, name in enumerate(names):
        rx, _ry = radii[index]
        cx = sun_x + rx
        cy = sun_y
        style = styles[name]
        r = style["r"]
        if name == "Saturn":
            body.append(_ellipse(cx, cy, r * 1.85, r * 0.52, "none", style["accent"], 4.0, -16))
        body.append(_circle(cx, cy, r, style["fill"], style["accent"], 1.5))
        if name == "Mercury":
            body.append(_circle(cx - r * 0.35, cy - r * 0.2, r * 0.18, style["accent"], style["accent"], 0.5))
            body.append(_circle(cx + r * 0.3, cy + r * 0.25, r * 0.14, style["accent"], style["accent"], 0.5))
        elif name == "Venus":
            body.append(_ellipse(cx, cy - r * 0.2, r * 0.7, r * 0.2, style["accent"], style["accent"], 0.5))
        elif name == "Earth":
            body.append(_ellipse(cx - r * 0.2, cy - r * 0.15, r * 0.45, r * 0.28, style["accent"], style["accent"], 0.5))
            body.append(_ellipse(cx + r * 0.3, cy + r * 0.3, r * 0.28, r * 0.2, style["accent"], style["accent"], 0.5))
            body.append(_ellipse(cx, cy + r * 0.45, r * 0.6, r * 0.16, "#ffffff", "#ffffff", 0.5))
        elif name == "Mars":
            body.append(_circle(cx - r * 0.3, cy - r * 0.2, r * 0.18, style["accent"], style["accent"], 0.5))
            body.append(_circle(cx + r * 0.35, cy + r * 0.25, r * 0.15, style["accent"], style["accent"], 0.5))
        elif name == "Jupiter":
            for offset in (-0.45, 0.0, 0.45):
                body.append(_ellipse(cx, cy + r * offset, r * 0.9, r * 0.13, style["accent"], style["accent"], 0.5))
            body.append(_circle(cx + r * 0.4, cy + r * 0.2, r * 0.2, "#ef4444", "#ef4444", 0.5))
        elif name == "Saturn":
            body.append(_ellipse(cx, cy, r * 0.82, r * 0.25, "none", style["accent"], 1.2))
        elif name == "Uranus":
            body.append(_ellipse(cx, cy, r * 0.9, r * 0.18, "none", style["accent"], 1.0))
        elif name == "Neptune":
            body.append(_circle(cx + r * 0.3, cy + r * 0.2, r * 0.22, "#1e3a8a", "#1e3a8a", 0.5))

        label_y = sun_y - r - 18 if index % 2 == 0 else sun_y + r + 28
        body.append(_text(cx, label_y, f"{index + 1}. {name}", 13, _INK, weight="bold"))

    body.append(_text(width / 2, height - 22, "Orbital paths and planet sizes are illustrative, not to scale.", 12, _MUTED))
    return _svg(width, height, "".join(body))


def _scene_center(element: dict, canvas_w: float, canvas_h: float) -> tuple[float, float]:
    x, y, w, h = _bbox(element.get("bbox"))
    if w or h:
        return x + w / 2, y + h / 2
    try:
        return float(element.get("x", canvas_w / 2)), float(element.get("y", canvas_h / 2))
    except (TypeError, ValueError):
        return canvas_w / 2, canvas_h / 2


def _bbox_edge_point(element: dict, target_x: float, target_y: float):
    """Return where a line from the element centre to a target leaves its bbox."""
    x, y, w, h = _bbox(element.get("bbox"))
    if not w and not h:
        return None
    cx, cy = x + w / 2, y + h / 2
    dx, dy = target_x - cx, target_y - cy
    if abs(dx) < 1e-6 and abs(dy) < 1e-6:
        return None
    tx = (w / 2) / abs(dx) if abs(dx) > 1e-6 else float("inf")
    ty = (h / 2) / abs(dy) if abs(dy) > 1e-6 else float("inf")
    scale = min(tx, ty)
    return cx + dx * scale, cy + dy * scale


def _arc_to_cubics(x1, y1, rx, ry, phi_deg, large_arc, sweep, x2, y2):
    """Convert one SVG elliptical arc to cubic Bezier commands."""
    if rx == 0 or ry == 0:
        return [("L", x2, y2)]
    rx, ry = abs(rx), abs(ry)
    phi = math.radians(phi_deg % 360)
    cos_phi, sin_phi = math.cos(phi), math.sin(phi)
    dx2, dy2 = (x1 - x2) / 2.0, (y1 - y2) / 2.0
    x1p = cos_phi * dx2 + sin_phi * dy2
    y1p = -sin_phi * dx2 + cos_phi * dy2
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:
        scale = math.sqrt(lam)
        rx *= scale
        ry *= scale
    numerator = max(0.0, rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p)
    denominator = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    coef = (1.0 if large_arc == sweep else -1.0) * math.sqrt(numerator / denominator) if denominator else 0.0
    cxp = coef * (rx * y1p / ry)
    cyp = coef * (-ry * x1p / rx)
    cx = cos_phi * cxp - sin_phi * cyp + (x1 + x2) / 2.0
    cy = sin_phi * cxp + cos_phi * cyp + (y1 + y2) / 2.0

    def angle(ux, uy, vx, vy):
        dot = ux * vx + uy * vy
        length = math.hypot(ux, uy) * math.hypot(vx, vy)
        if length == 0:
            return 0.0
        value = max(-1.0, min(1.0, dot / length))
        sign = -1.0 if (ux * vy - uy * vx) < 0 else 1.0
        return sign * math.acos(value)

    ux, uy = (x1p - cxp) / rx, (y1p - cyp) / ry
    vx, vy = (-x1p - cxp) / rx, (-y1p - cyp) / ry
    theta1 = angle(1.0, 0.0, ux, uy)
    delta = angle(ux, uy, vx, vy)
    if not sweep and delta > 0:
        delta -= 2 * math.pi
    elif sweep and delta < 0:
        delta += 2 * math.pi
    segments = max(1, int(math.ceil(abs(delta) / (math.pi / 2))))
    step = delta / segments
    out = []
    for index in range(segments):
        a1 = theta1 + index * step
        a2 = a1 + step
        alpha = (4.0 / 3.0) * math.tan((a2 - a1) / 4.0)
        p1x = cx + rx * math.cos(a1) * cos_phi - ry * math.sin(a1) * sin_phi
        p1y = cy + rx * math.cos(a1) * sin_phi + ry * math.sin(a1) * cos_phi
        p2x = cx + rx * math.cos(a2) * cos_phi - ry * math.sin(a2) * sin_phi
        p2y = cy + rx * math.cos(a2) * sin_phi + ry * math.sin(a2) * cos_phi
        c1x = p1x + alpha * (-rx * math.sin(a1) * cos_phi - ry * math.cos(a1) * sin_phi)
        c1y = p1y + alpha * (-rx * math.sin(a1) * sin_phi + ry * math.cos(a1) * cos_phi)
        c2x = p2x - alpha * (-rx * math.sin(a2) * cos_phi - ry * math.cos(a2) * sin_phi)
        c2y = p2y - alpha * (-rx * math.sin(a2) * sin_phi + ry * math.cos(a2) * cos_phi)
        out.append(("C", c1x, c1y, c2x, c2y, p2x, p2y))
    return out


def _convert_path_arcs(d: str) -> str:
    """Rewrite SVG arcs as cubics; fpdf's arc approximation can fail on tiny negatives."""
    text = str(d or "")
    tokens = re.findall(r"[MmLlHhVvCcSsQqTtAaZz]|[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?", text)
    if not tokens or not any(token in "Aa" for token in tokens):
        return text
    index = 0
    command = ""
    current_x = current_y = start_x = start_y = 0.0
    out = []

    def take(count):
        nonlocal index
        values = []
        for _ in range(count):
            if index >= len(tokens):
                raise DiagramRenderError("Unsafe or incomplete SVG path.")
            values.append(float(tokens[index]))
            index += 1
        return values

    def fmt(value):
        return f"{value:.4f}".rstrip("0").rstrip(".")

    while index < len(tokens):
        if tokens[index].isalpha():
            command = tokens[index]
            index += 1
            if command in "Zz":
                out.append("Z")
                current_x, current_y = start_x, start_y
                continue
        elif not command:
            raise DiagramRenderError("Unsafe SVG path.")
        upper = command.upper()
        relative = command.islower()
        if upper == "M":
            x, y = take(2)
            if relative:
                x, y = current_x + x, current_y + y
            current_x, current_y = x, y
            start_x, start_y = x, y
            out.append(f"M {fmt(x)} {fmt(y)}")
            command = "l" if relative else "L"
        elif upper == "L":
            x, y = take(2)
            if relative:
                x, y = current_x + x, current_y + y
            current_x, current_y = x, y
            out.append(f"L {fmt(x)} {fmt(y)}")
        elif upper == "H":
            x = take(1)[0]
            if relative:
                x = current_x + x
            current_x = x
            out.append(f"L {fmt(x)} {fmt(current_y)}")
        elif upper == "V":
            y = take(1)[0]
            if relative:
                y = current_y + y
            current_y = y
            out.append(f"L {fmt(current_x)} {fmt(y)}")
        elif upper == "C":
            values = take(6)
            if relative:
                values = [values[i] + (current_x if i % 2 == 0 else current_y) for i in range(6)]
            current_x, current_y = values[4], values[5]
            out.append("C " + " ".join(fmt(value) for value in values))
        elif upper == "S":
            values = take(4)
            if relative:
                values = [values[i] + (current_x if i % 2 == 0 else current_y) for i in range(4)]
            current_x, current_y = values[2], values[3]
            out.append("S " + " ".join(fmt(value) for value in values))
        elif upper == "Q":
            values = take(4)
            if relative:
                values = [values[i] + (current_x if i % 2 == 0 else current_y) for i in range(4)]
            current_x, current_y = values[2], values[3]
            out.append("Q " + " ".join(fmt(value) for value in values))
        elif upper == "T":
            values = take(2)
            if relative:
                values = [values[0] + current_x, values[1] + current_y]
            current_x, current_y = values[0], values[1]
            out.append("T " + " ".join(fmt(value) for value in values))
        elif upper == "A":
            rx, ry, phi, large_arc, sweep, x, y = take(7)
            if relative:
                x, y = current_x + x, current_y + y
            for item in _arc_to_cubics(current_x, current_y, rx, ry, phi, int(large_arc), int(sweep), x, y):
                out.append(item[0] + " " + " ".join(fmt(value) for value in item[1:]))
            current_x, current_y = x, y
        else:
            raise DiagramRenderError("Unsupported SVG path command.")
    return " ".join(out)


def _safe_path(d: Any) -> str:
    text = str(d or "").strip()
    if not text or len(text) > 12000:
        raise DiagramRenderError("Unsafe or empty SVG path.")
    if not re.fullmatch(r"[MmLlHhVvCcSsQqTtAaZz0-9eE+\-.,\s]+", text):
        raise DiagramRenderError("Unsupported SVG path command.")
    return text


@register("generic_scene")
def render_generic_scene(diagram: dict) -> str:
    scene = diagram.get("scene") or {}
    elements = [element for element in scene.get("elements", []) if isinstance(element, dict)]
    if not elements:
        raise DiagramRenderError("No diagram elements to render.")
    try:
        canvas_w = max(100.0, min(4000.0, float((scene.get("canvas") or [1000, 700])[0])))
        canvas_h = max(100.0, min(4000.0, float((scene.get("canvas") or [1000, 700])[1])))
    except (TypeError, ValueError, IndexError):
        canvas_w, canvas_h = 1000.0, 700.0

    by_id = {str(element.get("id") or f"e{index}"): element for index, element in enumerate(elements)}
    body: list[str] = []
    body.append(_text(canvas_w / 2, 30, diagram.get("title") or "", 22, _BLUE, weight="bold"))

    for element in elements:
        kind = str(element.get("kind") or "").lower()
        if kind == "connector":
            continue
        shape = str(element.get("shape") or "").lower()
        x, y, w, h = _bbox(element.get("bbox"))
        label = clean_text(element.get("label") or element.get("text"), 1000)
        if kind == "text" or shape == "text":
            anchor = "middle"
            if w or h:
                centre_x = x + w / 2
                if centre_x < canvas_w * 0.35:
                    tx, anchor = x, "start"
                elif centre_x > canvas_w * 0.65:
                    tx, anchor = x + w, "end"
                else:
                    tx = centre_x
                ty = y + h / 2
            else:
                try:
                    tx = float(element.get("x", canvas_w / 2))
                    ty = float(element.get("y", canvas_h / 2))
                except (TypeError, ValueError):
                    tx, ty = canvas_w / 2, canvas_h / 2
            body.append(_text(tx, ty, label or element.get("text", ""), 14, _INK, anchor=anchor))
            continue
        points = element.get("points") or []
        nums = [float(v) for v in points if isinstance(v, (int, float))]
        if shape == "rect":
            body.append(_rect(x, y, w, h, "#ffffff", _INK, 1.5, 6))
        elif shape == "circle":
            body.append(_circle(x + w / 2, y + h / 2, min(w, h) / 2, "#ffffff", _INK, 1.5))
        elif shape == "ellipse":
            body.append(_ellipse(x + w / 2, y + h / 2, w / 2, h / 2, "#ffffff", _INK, 1.5))
        elif shape == "line":
            if len(nums) >= 4:
                body.append(_line(nums[0], nums[1], nums[2], nums[3], _INK, 1.5))
            else:
                body.append(_line(x, y, x + w, y + h, _INK, 1.5))
        elif shape == "arrow":
            body.append(_arrow(x, y, x + w, y + h, _INK, 1.8))
        elif shape in {"polygon", "diamond", "triangle"}:
            if shape == "diamond" and len(nums) < 6:
                nums = [x + w / 2, y, x + w, y + h / 2, x + w / 2, y + h, x, y + h / 2]
            elif shape == "triangle" and len(nums) < 6:
                nums = [x + w / 2, y, x + w, y + h, x, y + h]
            if len(nums) >= 6:
                body.append(f'<polygon points="{" ".join(f"{v:.2f}" for v in nums)}" fill="#ffffff" stroke="{_INK}" stroke-width="1.5"/>')
        elif shape == "polyline":
            if len(nums) >= 4:
                body.append(f'<polyline points="{" ".join(f"{v:.2f}" for v in nums)}" fill="none" stroke="{_INK}" stroke-width="1.5"/>')
        elif shape == "path":
            path_d = _convert_path_arcs(element.get("d") or "")
            body.append(f'<path d="{_x(_safe_path(path_d))}" fill="none" stroke="{_INK}" stroke-width="1.5"/>')
        if label and shape not in {"text"}:
            body.append(_text(x + w / 2, y + h / 2 + 5, label, 13, _INK))

    for element in elements:
        if str(element.get("kind") or "").lower() != "connector":
            continue
        source = by_id.get(str(element.get("from") or ""))
        target = by_id.get(str(element.get("to") or ""))
        points = [float(value) for value in element.get("points") or [] if isinstance(value, (int, float))]
        if len(points) >= 4:
            x1, y1, x2, y2 = points[:4]
        else:
            if not source or not target:
                continue
            x1, y1 = _scene_center(source, canvas_w, canvas_h)
            x2, y2 = _scene_center(target, canvas_w, canvas_h)
        if source:
            edge = _bbox_edge_point(source, x2, y2)
            if edge:
                x1, y1 = edge
        arrow = str(element.get("arrow") or "").lower()
        if arrow in {"end", "both", "yes", "true"}:
            body.append(_arrow(x1, y1, x2, y2, _INK, 1.8))
        else:
            body.append(_line(x1, y1, x2, y2, _INK, 1.8))
        label = clean_text(element.get("label"), 500)
        if label:
            body.append(_text((x1 + x2) / 2, (y1 + y2) / 2 - 6, label, 12, _MUTED))

    # A sparse scene used to keep its full 1000x1000 canvas, which left a large
    # blank area in the PDF. Trim to the drawn content (with a small margin) so
    # the figure fills the available width instead of floating in whitespace.
    element_xs: list[float] = []
    element_ys: list[float] = []
    for element in elements:
        x, y, w, h = _bbox(element.get("bbox"))
        if w or h:
            element_xs.extend((x, x + w))
            element_ys.extend((y, y + h))
        points = [float(value) for value in element.get("points") or [] if isinstance(value, (int, float))]
        for index in range(0, len(points) - 1, 2):
            element_xs.append(points[index])
            element_ys.append(points[index + 1])
        if str(element.get("kind") or "").lower() == "text" or str(element.get("shape") or "").lower() == "text":
            try:
                text_x = float(element.get("x", 0))
                text_y = float(element.get("y", 0))
            except (TypeError, ValueError):
                text_x = text_y = 0.0
            if text_x or text_y:
                element_xs.append(text_x)
                element_ys.extend((text_y - 14, text_y + 6))

    if not element_xs or not element_ys:
        return _svg(canvas_w, canvas_h, "".join(body))

    min_x, max_x = min(element_xs), max(element_xs)
    min_y, max_y = min(element_ys), max(element_ys)
    content_w = max(1.0, max_x - min_x)
    content_h = max(1.0, max_y - min_y)
    if content_w >= canvas_w * 0.75 and content_h >= canvas_h * 0.75:
        return _svg(canvas_w, canvas_h, "".join(body))

    title = clean_text(diagram.get("title") or "", 500)
    if title:
        min_x = min(min_x, canvas_w / 2 - 140)
        max_x = max(max_x, canvas_w / 2 + 140)
        min_y = min(min_y, 8.0)
        max_y = max(max_y, 46.0)

    pad = 18.0
    view_w = max(220.0, max_x - min_x + pad * 2)
    view_h = max(150.0, max_y - min_y + pad * 2)
    offset_x = pad - min_x
    offset_y = pad - min_y
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{view_w:.2f}" height="{view_h:.2f}" '
        f'viewBox="0 0 {view_w:.2f} {view_h:.2f}">'
        f'<rect x="0" y="0" width="{view_w:.2f}" height="{view_h:.2f}" fill="#ffffff"/>'
        f'<g transform="translate({offset_x:.2f} {offset_y:.2f})">{"".join(body)}</g></svg>'
    )


@register("flowchart")
def render_flowchart(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    nodes = [node for node in data.get("nodes", []) if isinstance(node, dict)]
    if not nodes:
        # Some vision models identify a flowchart and its labels but return no
        # scene nodes. Build a conservative vertical flow from the labels so
        # the user still gets a vector diagram instead of a raster crop.
        labels = []
        for label in diagram.get("labels") or []:
            text = clean_text(label.get("text") if isinstance(label, dict) else label, 500)
            if text and text not in labels:
                labels.append(text)
        preferred = [label for label in labels if label[:1].isupper()]
        selected = preferred if len(preferred) >= 2 else labels
        selected = selected[:5]
        if selected:
            data = dict(data)
            data["nodes"] = [
                {"id": f"n{index + 1}", "label": label, "x": 300, "y": 110 + index * 120,
                 "w": 400, "h": 70}
                for index, label in enumerate(selected)
            ]
            data["edges"] = [
                {"from": f"n{index + 1}", "to": f"n{index + 2}"}
                for index in range(max(0, len(selected) - 1))
            ]
            nodes = data["nodes"]
        else:
            return render_generic_scene(diagram)
    width, height = 1000.0, 700.0
    body = [_text(width / 2, 32, diagram.get("title") or "Flowchart", 22, _BLUE, weight="bold")]
    positions: dict[str, tuple[float, float, float, float]] = {}
    count = max(1, len(nodes))
    for index, node in enumerate(nodes):
        node_id = str(node.get("id") or f"n{index}")
        x = float(node.get("x", 80 + (index % 2) * 480))
        y = float(node.get("y", 80 + (index // 2) * 130))
        w = float(node.get("w", 360))
        h = float(node.get("h", 70))
        positions[node_id] = (x, y, w, h)
        shape = str(node.get("shape") or "rect").lower()
        if shape == "diamond":
            cx, cy = x + w / 2, y + h / 2
            body.append(f'<polygon points="{cx:.2f},{y:.2f} {x + w:.2f},{cy:.2f} {cx:.2f},{y + h:.2f} {x:.2f},{cy:.2f}" fill="#ffffff" stroke="{_INK}" stroke-width="1.5"/>')
        elif shape == "circle":
            body.append(_circle(x + w / 2, y + h / 2, min(w, h) / 2, "#ffffff", _INK, 1.5))
        else:
            body.append(_rect(x, y, w, h, "#ffffff", _INK, 1.5, 10))
        body.append(_text(x + w / 2, y + h / 2 + 5, node.get("label") or node_id, 14, _INK))
    for edge in data.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = positions.get(str(edge.get("from") or ""))
        target = positions.get(str(edge.get("to") or ""))
        if not source or not target:
            continue
        x1, y1 = source[0] + source[2] / 2, source[1] + source[3]
        x2, y2 = target[0] + target[2] / 2, target[1]
        body.append(_arrow(x1, y1, x2, y2, _INK, 1.8))
        label = clean_text(edge.get("label"), 500)
        if label:
            body.append(_text((x1 + x2) / 2, (y1 + y2) / 2 - 5, label, 12, _MUTED))
    return _svg(width, height, "".join(body))


@register("geometry")
def render_geometry(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    points = [point for point in data.get("points", []) if isinstance(point, dict)]
    if not points:
        return render_generic_scene(diagram)
    width, height = 1000.0, 700.0
    body = [_text(width / 2, 32, diagram.get("title") or "Geometry", 22, _BLUE, weight="bold")]
    coords: dict[str, tuple[float, float]] = {}
    for index, point in enumerate(points):
        point_id = str(point.get("id") or f"p{index}")
        x = float(point.get("x", 100 + index * 100))
        y = float(point.get("y", 400))
        coords[point_id] = (x, y)
        body.append(_circle(x, y, 3.5, _BLUE, _BLUE, 1))
        body.append(_text(x, y - 10, point.get("label") or point_id, 13, _INK))
    for segment in data.get("segments", []):
        if not isinstance(segment, dict):
            continue
        a = coords.get(str(segment.get("from") or ""))
        b = coords.get(str(segment.get("to") or ""))
        if a and b:
            body.append(_line(a[0], a[1], b[0], b[1], _INK, 2))
            label = clean_text(segment.get("label"), 500)
            if label:
                body.append(_text((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 - 8, label, 12, _MUTED))
    for circle in data.get("circles", []):
        if not isinstance(circle, dict):
            continue
        center = coords.get(str(circle.get("center") or ""))
        if center:
            body.append(_circle(center[0], center[1], float(circle.get("radius", 60)), "none", _BLUE, 2))
            if circle.get("label"):
                body.append(_text(center[0], center[1] - float(circle.get("radius", 60)) - 8, circle.get("label"), 12, _MUTED))
    return _svg(width, height, "".join(body))


@register("circuit")
def render_circuit(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    components = [item for item in data.get("components", []) if isinstance(item, dict)]
    if not components:
        return render_generic_scene(diagram)
    width, height = 1000.0, 620.0
    body = [_text(width / 2, 32, diagram.get("title") or "Circuit", 22, _BLUE, weight="bold")]
    positions: dict[str, tuple[float, float]] = {}
    for index, component in enumerate(components):
        component_id = str(component.get("id") or f"c{index}")
        x = float(component.get("x", 120 + (index % 4) * 210))
        y = float(component.get("y", 180 + (index // 4) * 170))
        positions[component_id] = (x, y)
        kind = str(component.get("type") or component.get("kind") or "box").lower()
        label = component.get("label") or kind
        if kind in {"battery", "cell"}:
            body.append(_line(x - 22, y - 24, x - 22, y + 24, _INK, 3))
            body.append(_line(x - 12, y - 14, x - 12, y + 14, _INK, 3))
            body.append(_line(x + 12, y - 24, x + 12, y + 24, _INK, 3))
            body.append(_line(x + 22, y - 14, x + 22, y + 14, _INK, 3))
        elif kind == "resistor":
            body.append(_rect(x - 35, y - 12, 70, 24, "#ffffff", _INK, 1.5, 2))
        elif kind == "lamp":
            body.append(_circle(x, y, 18, "#fef3c7", _INK, 1.5))
            body.append(_line(x - 10, y - 10, x + 10, y + 10, _INK, 1.5))
            body.append(_line(x - 10, y + 10, x + 10, y - 10, _INK, 1.5))
        elif kind == "switch":
            body.append(_circle(x - 22, y, 3, _INK, _INK, 0.5))
            body.append(_circle(x + 22, y, 3, _INK, _INK, 0.5))
            body.append(_line(x - 22, y, x + 12, y - 20, _INK, 2))
        elif kind == "capacitor":
            body.append(_line(x - 8, y - 22, x - 8, y + 22, _INK, 2.5))
            body.append(_line(x + 8, y - 22, x + 8, y + 22, _INK, 2.5))
        else:
            body.append(_rect(x - 38, y - 22, 76, 44, "#ffffff", _INK, 1.5, 5))
        body.append(_text(x, y + 42, label, 12, _INK))
    for wire in data.get("wires", []):
        if not isinstance(wire, dict):
            continue
        a = positions.get(str(wire.get("from") or ""))
        b = positions.get(str(wire.get("to") or ""))
        if a and b:
            body.append(_line(a[0], a[1], b[0], b[1], _INK, 1.5))
    return _svg(width, height, "".join(body))


@register("molecule")
def render_molecule(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    atoms = [atom for atom in data.get("atoms", []) if isinstance(atom, dict)]
    if not atoms:
        return render_generic_scene(diagram)
    width, height = 1000.0, 620.0
    body = [_text(width / 2, 32, diagram.get("title") or "Molecular structure", 22, _BLUE, weight="bold")]
    coords: dict[str, tuple[float, float]] = {}
    for index, atom in enumerate(atoms):
        atom_id = str(atom.get("id") or f"a{index}")
        angle = (2 * math.pi * index / max(1, len(atoms))) - math.pi / 2
        radius = float(atom.get("radius", 170))
        x = float(atom.get("x", width / 2 + radius * math.cos(angle)))
        y = float(atom.get("y", height / 2 + radius * math.sin(angle)))
        coords[atom_id] = (x, y)
    for bond in data.get("bonds", []):
        if not isinstance(bond, dict):
            continue
        a = coords.get(str(bond.get("from") or ""))
        b = coords.get(str(bond.get("to") or ""))
        if not a or not b:
            continue
        order = max(1, min(3, int(bond.get("order", 1))))
        dx, dy = b[0] - a[0], b[1] - a[1]
        length = max(1.0, math.hypot(dx, dy))
        nx, ny = -dy / length, dx / length
        for offset in range(order):
            shift = (offset - (order - 1) / 2) * 6
            body.append(_line(a[0] + nx * shift, a[1] + ny * shift, b[0] + nx * shift, b[1] + ny * shift, _INK, 1.6))
    colors = {"H": "#f8fafc", "O": "#f87171", "N": "#60a5fa", "C": "#334155", "S": "#fbbf24", "P": "#fb923c", "Cl": "#22c55e"}
    for atom in atoms:
        atom_id = str(atom.get("id") or "")
        if atom_id not in coords:
            continue
        x, y = coords[atom_id]
        element = clean_text(atom.get("element") or atom.get("label") or "C", 10)
        fill = colors.get(element, "#e2e8f0")
        text_fill = "#ffffff" if element in {"C", "O", "N"} else _INK
        body.append(_circle(x, y, 24, fill, _INK, 1.5))
        body.append(_text(x, y + 5, element, 13, text_fill, weight="bold"))
    return _svg(width, height, "".join(body))


@register("chart")
def render_chart(diagram: dict) -> str:
    data = diagram.get("template_data") or {}
    labels = [clean_text(item, 100) for item in (data.get("labels") or [])]
    values = []
    for value in data.get("values") or []:
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            values.append(0.0)
    if not values and isinstance(data.get("series"), list):
        labels = [clean_text(item.get("label"), 100) for item in data["series"] if isinstance(item, dict)]
        values = [float(item.get("value", 0)) for item in data["series"] if isinstance(item, dict)]
    if not values:
        return render_generic_scene(diagram)
    width, height = 1000.0, 620.0
    body = []
    title = diagram.get("title")
    if title is None:
        title = "Chart"
    if title:
        body.append(_text(width / 2, 32, title, 22, _BLUE, weight="bold"))
    chart_type = str(data.get("chart_type") or data.get("type") or "bar").lower()
    if chart_type == "pie":
        total = sum(max(0.0, value) for value in values) or 1.0
        colors = ["#1e3a8a", "#3b82f6", "#60a5fa", "#93c5fd", "#bfdbfe", "#f59e0b", "#22c55e", "#f87171"]
        cx, cy, radius = 360.0, 330.0, 180.0
        start = -math.pi / 2
        for index, value in enumerate(values):
            angle = 2 * math.pi * max(0.0, value) / total
            end = start + angle
            x1, y1 = cx + radius * math.cos(start), cy + radius * math.sin(start)
            x2, y2 = cx + radius * math.cos(end), cy + radius * math.sin(end)
            large = 1 if angle > math.pi else 0
            body.append(f'<path d="M {cx:.2f} {cy:.2f} L {x1:.2f} {y1:.2f} A {radius:.2f} {radius:.2f} 0 {large} 1 {x2:.2f} {y2:.2f} Z" fill="{colors[index % len(colors)]}" stroke="#ffffff" stroke-width="1"/>')
            mid = (start + end) / 2
            label = labels[index] if index < len(labels) else str(index + 1)
            percent = (max(0.0, value) / total) * 100
            body.append(_text(cx + radius * 0.62 * math.cos(mid), cy + radius * 0.62 * math.sin(mid), f"{label} {percent:.0f}%", 12, "#ffffff"))
            start = end
    else:
        left, top, right, bottom = 100.0, 90.0, 930.0, 520.0
        body.append(_line(left, bottom, right, bottom, _INK, 1.5))
        body.append(_line(left, top, left, bottom, _INK, 1.5))
        max_value = max(values) or 1.0
        count = max(1, len(values))
        slot = (right - left) / count
        if chart_type == "line":
            points = []
            for index, value in enumerate(values):
                x = left + slot * (index + 0.5)
                y = bottom - (value / max_value) * (bottom - top)
                points.append((x, y))
                body.append(_circle(x, y, 4, _BLUE_2, _BLUE_2, 1))
                body.append(_text(x, y - 10, f"{value:g}", 11, _INK))
            for first, second in zip(points, points[1:]):
                body.append(_line(first[0], first[1], second[0], second[1], _BLUE_2, 2.5))
        elif chart_type == "ogive":
            # Ogive: cumulative frequency line chart
            cum_values = []
            cumulative = 0.0
            for value in values:
                cumulative += max(0.0, value)
                cum_values.append(cumulative)
            max_cum = max(cum_values) or 1.0
            count = max(1, len(cum_values))
            for index, cum_val in enumerate(cum_values):
                x = left + slot * (index + 0.5)
                y = bottom - (cum_val / max_cum) * (bottom - top)
                body.append(_circle(x, y, 4, _BLUE_2, _BLUE_2, 1))
                body.append(_text(x, y - 10, f"{cum_val:g}", 11, _INK))
            # Draw cumulative line connecting all points
            cum_points = []
            for index, cum_val in enumerate(cum_values):
                x = left + slot * (index + 0.5)
                y = bottom - (cum_val / max_cum) * (bottom - top)
                cum_points.append((x, y))
            for first, second in zip(cum_points, cum_points[1:]):
                body.append(_line(first[0], first[1], second[0], second[1], _BLUE_2, 2.5))
        else:
            for index, value in enumerate(values):
                bar_w = slot * 0.55
                x = left + slot * index + (slot - bar_w) / 2
                bar_h = (value / max_value) * (bottom - top)
                body.append(_rect(x, bottom - bar_h, bar_w, bar_h, _BLUE_2, _BLUE, 1.2, 3))
                body.append(_text(x + bar_w / 2, bottom - bar_h - 8, f"{value:g}", 11, _INK))
        for index, label in enumerate(labels[:count]):
            body.append(_text(left + slot * (index + 0.5), bottom + 24, label, 12, _MUTED))
    return _svg(width, height, "".join(body))


# Universal labelled-figure aliases. These use the same structured scene
# renderer as any other subject, so new subjects do not need a hardcoded
# template. If a model returns only labels and no scene, the schema layer
# keeps the original crop instead of asking for an impossible SVG.
for _generic_alias in (
    "labelled_figure", "labeled_figure", "anatomy", "human_body", "heart",
    "cell", "plant", "map", "illustration", "diagram", "other", "unknown",
):
    _RENDERERS.setdefault(_generic_alias, render_generic_scene)


def _pencil_style_svg(svg: str) -> str:
    """Turn a clean colour SVG into a readable graphite notebook sketch.

    The transformation is deliberately generic: every diagram template keeps
    its own geometry, labels and connectors. Only the palette and line texture
    change, so unsupported subjects do not need a separate renderer.
    """
    def replace_colour(match: re.Match) -> str:
        attribute = match.group(1).lower()
        colour = match.group(2).lower()
        if attribute == "fill":
            if colour in {"#ffffff", "#fff", "#f8fafc", "#f9fafb"}:
                return 'fill="#fbf8ef"'
            return 'fill="#e8e3d7"'
        return 'stroke="#3f3f46"'

    svg = re.sub(r'\b(fill|stroke)="(#[0-9a-fA-F]{3,6})"', replace_colour, svg)

    def add_pencil_edges(match: re.Match) -> str:
        tag = match.group(0)
        if "stroke-linecap=" in tag:
            return tag
        if tag.endswith("/>"):
            return tag[:-2] + ' stroke-linecap="round" stroke-linejoin="round"/>'
        return tag[:-1] + ' stroke-linecap="round" stroke-linejoin="round">'

    # Keep the SVG inside the subset understood by the local PDF engine.
    # A turbulence filter looks nice in a browser but is not portable to FPDF,
    # so the pencil effect is achieved with a graphite palette and rounded
    # line joins instead of unsupported filter primitives.
    svg = re.sub(
        r'<(?:rect|circle|ellipse|line|path|polygon|polyline)\b[^>]*>',
        add_pencil_edges,
        svg,
    )
    # Keep labels dark even though shapes use the light graphite fill.
    svg = re.sub(r'(<text\b[^>]*\bfill=")#e8e3d7(")', r'\1#3f3f46\2', svg)
    return svg


_STYLE_ACCENTS = {
    "medical": ("#f0fdfa", "#0f766e"),
    "molecule2d": ("#f5f3ff", "#5b21b6"),
    "structure3d": ("#eff6ff", "#1e3a8a"),
    "topographic": ("#fefce8", "#92400e"),
}


def _tinted_style_svg(svg: str, surface: str, accent: str) -> str:
    """Apply a subject palette while keeping every label readable.

    Only white surfaces and the standard ink stroke change. Template colours
    are left alone so a multi-colour figure does not turn into a flat block.
    """
    def replace_colour(match: re.Match) -> str:
        attribute = match.group(1).lower()
        colour = match.group(2).lower()
        if attribute == "fill":
            if colour in {"#ffffff", "#fff", "#f8fafc", "#f9fafb"}:
                return f'fill="{surface}"'
            return match.group(0)
        if colour in {"#0f172a", "#111827", "#1f2937"}:
            return f'stroke="{accent}"'
        return match.group(0)

    svg = re.sub(r'\b(fill|stroke)="(#[0-9a-fA-F]{3,6})"', replace_colour, svg)
    svg = re.sub(r'(<text\b[^>]*\bfill=")[^"]*(")', r'\1#0f172a\2', svg)
    return svg


def _line_style_svg(svg: str) -> str:
    """Monochrome line art for Clean Vector / Schematic / Outline modes."""
    def replace_colour(match: re.Match) -> str:
        attribute = match.group(1).lower()
        colour = match.group(2).lower()
        if attribute == "fill":
            if colour in {"#ffffff", "#fff", "#f8fafc", "#f9fafb"}:
                return 'fill="#ffffff"'
            return 'fill="none"'
        return 'stroke="#0f172a"'

    svg = re.sub(r'\b(fill|stroke)="(#[0-9a-fA-F]{3,6})"', replace_colour, svg)
    svg = re.sub(r'(<text\b[^>]*\bfill=")[^"]*(")', r'\1#0f172a\2', svg)
    return svg


def render_diagram_svg(diagram: dict, style: str = "color") -> bytes:
    """Render a normalised diagram spec into safe SVG bytes."""
    if not isinstance(diagram, dict):
        raise DiagramRenderError("Invalid diagram specification.")
    if diagram.get("recreation_mode") == "trace":
        # A source-accurate vector trace takes priority over any AI scene.
        # Tracing preserves the original labels, leader lines and anatomy.
        if trace_data_url is None:
            raise DiagramRenderError("Vector tracing is not available.")
        source_preview = str(diagram.get("source_preview") or "")
        if not source_preview.startswith("data:image/"):
            raise DiagramRenderError("Vector trace requires a saved source crop.")
        try:
            svg_bytes, _quality = trace_data_url(source_preview, style=style)
        except TraceQualityError as exc:
            raise DiagramRenderError(str(exc) or "The vector trace was not accepted.")
        if not svg_bytes.startswith(b"<svg"):
            raise DiagramRenderError("Vector trace produced invalid SVG.")
        return svg_bytes
    if _label_has_arabic(diagram):
        # The PDF layer preserves the original crop for RTL diagram labels
        # rather than risking broken shaping in an SVG text layer.
        raise DiagramRenderError("RTL diagram labels require the original crop.")
    diagram_type = str(diagram.get("type") or "").lower()
    has_scene = bool(diagram.get("scene", {}).get("elements"))
    has_template = bool(diagram.get("template_data"))
    label_count = len(diagram.get("labels") or [])
    if not has_scene and not has_template:
        # Flowcharts are the one template that can safely reconstruct a
        # conservative sequence from detected labels alone. Every other
        # subject must fall back to the source crop rather than invent shapes.
        if not (diagram_type == "flowchart" and label_count >= 2):
            raise DiagramRenderError(
                "The source diagram is used for accuracy because a reliable vector structure is not available."
            )
    renderer = _RENDERERS.get(diagram_type)
    if renderer:
        svg = renderer(diagram)
    elif has_scene:
        svg = render_generic_scene(diagram)
    else:
        raise DiagramRenderError(
            "The source diagram is used for accuracy because a reliable vector structure is not available."
        )
    if not svg.startswith("<svg"):
        raise DiagramRenderError("Renderer returned invalid SVG.")
    normalised_style = normalise_diagram_style(style)
    if normalised_style == "pencil":
        svg = _pencil_style_svg(svg)
    elif normalised_style in {"schematic", "outline"}:
        svg = _line_style_svg(svg)
    elif normalised_style in _STYLE_ACCENTS:
        surface, accent = _STYLE_ACCENTS[normalised_style]
        svg = _tinted_style_svg(svg, surface, accent)
    return svg.encode("utf-8")


def svg_dimensions(svg_bytes: bytes) -> tuple[float, float]:
    text = svg_bytes.decode("utf-8", errors="ignore")[:2000]
    match = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', text)
    if match:
        return float(match.group(1)), float(match.group(2))
    width = re.search(r'width="([\d.]+)"', text)
    height = re.search(r'height="([\d.]+)"', text)
    if width and height:
        return float(width.group(1)), float(height.group(1))
    return 1000.0, 700.0
