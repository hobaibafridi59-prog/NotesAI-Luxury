"""Faithful raster-to-vector tracing for NotesAI diagrams.

The AI is useful for understanding labels and page structure, but it is not a
reliable anatomical illustrator. For line-art diagrams we therefore trace the
actual source crop into vector contours. This preserves the visible structure,
proportions, labels and leader lines instead of substituting unrelated boxes
and circles.

The tracer is deliberately dependency-light: Pillow plus the Python standard
library. It uses marching squares, contour chaining, Ramer-Douglas-Peucker
simplification and an even-odd SVG fill. A scanline structural-match check
compares the traced contours with the source mask before the trace is accepted.
"""

from __future__ import annotations

import base64
import hashlib
import io
import math
from collections import OrderedDict
from typing import Any

from PIL import Image


class TraceQualityError(RuntimeError):
    """Raised when a source crop cannot be traced faithfully enough."""


_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_MAX = 16


def _otsu_threshold(histogram: list[int]) -> int:
    total = sum(histogram)
    if total <= 0:
        return 128
    sum_all = sum(index * count for index, count in enumerate(histogram))
    sum_background = 0
    weight_background = 0
    best_variance = -1.0
    best_threshold = 128
    for threshold in range(256):
        weight_background += histogram[threshold]
        if weight_background == 0:
            continue
        weight_foreground = total - weight_background
        if weight_foreground == 0:
            break
        sum_background += threshold * histogram[threshold]
        mean_background = sum_background / weight_background
        mean_foreground = (sum_all - sum_background) / weight_foreground
        variance = weight_background * weight_foreground * (mean_background - mean_foreground) ** 2
        if variance > best_variance:
            best_variance = variance
            best_threshold = threshold
    return best_threshold


def _line_art_stats(image: Image.Image) -> dict[str, float]:
    """Estimate whether a crop is a light-background line drawing.

    Scanned pages are often grey rather than pure white, so the background
    level is measured from the image itself instead of assuming #ffffff.
    """
    sample = image.copy()
    sample.thumbnail((180, 180), Image.LANCZOS)
    pixels = list(sample.getdata())
    total = max(1, len(pixels))
    grays = sorted(
        int(0.299 * red + 0.587 * green + 0.114 * blue)
        for red, green, blue in pixels
    )

    def percentile(value: float) -> int:
        return grays[min(total - 1, max(0, int(value * total)))]

    background = percentile(0.90)
    ink = percentile(0.02)
    contrast = max(0, background - ink)
    ink_fraction = (
        sum(1 for gray in grays if gray < background - contrast * 0.35) / total
    )
    background_fraction = (
        sum(1 for gray in grays if gray > background - contrast * 0.18) / total
    )
    chroma = sum(max(r, g, b) - min(r, g, b) for r, g, b in pixels) / total
    return {
        "background": background,
        "ink": ink,
        "contrast": contrast,
        "ink_fraction": ink_fraction,
        "background_fraction": background_fraction,
        "light_fraction": background_fraction,
        "dark_fraction": ink_fraction,
        "mean_chroma": chroma,
    }


def _rdp(points: list[tuple[float, float]], epsilon: float) -> list[tuple[float, float]]:
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = True
    keep[-1] = True
    stack = [(0, len(points) - 1)]
    epsilon_sq = epsilon * epsilon
    while stack:
        start, end = stack.pop()
        if end <= start + 1:
            continue
        x1, y1 = points[start]
        x2, y2 = points[end]
        dx, dy = x2 - x1, y2 - y1
        denominator = dx * dx + dy * dy
        farthest = -1.0
        farthest_index = -1
        for index in range(start + 1, end):
            px, py = points[index]
            if denominator <= 1e-12:
                distance = (px - x1) ** 2 + (py - y1) ** 2
            else:
                t = ((px - x1) * dx + (py - y1) * dy) / denominator
                t = max(0.0, min(1.0, t))
                qx, qy = x1 + t * dx, y1 + t * dy
                distance = (px - qx) ** 2 + (py - qy) ** 2
            if distance > farthest:
                farthest = distance
                farthest_index = index
        if farthest > epsilon_sq and farthest_index > start:
            keep[farthest_index] = True
            stack.append((start, farthest_index))
            stack.append((farthest_index, end))
    return [point for point, selected in zip(points, keep) if selected]


def _contour_path_d(contours: list[list[tuple[float, float]]]) -> str:
    parts: list[str] = []
    for contour in contours:
        if len(contour) < 3:
            continue
        x0, y0 = contour[0]
        pieces = [f"M {x0:.1f} {y0:.1f}"]
        for x, y in contour[1:]:
            pieces.append(f"L {x:.1f} {y:.1f}")
        pieces.append("Z")
        parts.append(" ".join(pieces))
    return " ".join(parts)


def _scanline_iou(
    contours: list[list[tuple[float, float]]],
    source_rows: list[bytearray],
    width: int,
    height: int,
) -> float:
    if not contours or width <= 0 or height <= 0:
        return 0.0
    edges: list[tuple[float, float, float, float]] = []
    for contour in contours:
        for index in range(len(contour)):
            x1, y1 = contour[index]
            x2, y2 = contour[(index + 1) % len(contour)]
            if y1 == y2:
                continue
            if y1 > y2:
                x1, y1, x2, y2 = x2, y2, x1, y1
            edges.append((x1, y1, x2, y2))
    if not edges:
        return 0.0
    step = max(1, height // 220)
    intersection = 0
    union = 0
    for row in range(0, height, step):
        y = row + 0.5
        crossings: list[float] = []
        for x1, y1, x2, y2 in edges:
            if y1 <= y < y2:
                crossings.append(x1 + (y - y1) * (x2 - x1) / (y2 - y1))
        if len(crossings) < 2:
            continue
        crossings.sort()
        source = source_rows[row]
        ink = sum(source)
        if ink == 0 and not crossings:
            continue
        covered = 0
        overlap = 0
        for index in range(0, len(crossings) - 1, 2):
            left = max(0, int(math.floor(crossings[index])))
            right = min(width, int(math.ceil(crossings[index + 1])))
            if right <= left:
                continue
            covered += right - left
            for x in range(left, right):
                if source[x]:
                    overlap += 1
        intersection += overlap
        union += ink + covered - overlap
    if union <= 0:
        return 1.0 if intersection == 0 else 0.0
    return max(0.0, min(1.0, intersection / union))


def trace_image(image: Image.Image, max_side: int = 900, tolerance: float = 0.20) -> dict[str, Any]:
    """Return a traced path string plus an honest structural-match report."""
    if image is None:
        raise TraceQualityError("No source crop is available for tracing.")
    stats = _line_art_stats(image)
    line_art = (
        stats["background_fraction"] >= 0.50
        and stats["contrast"] >= 35
        and 0.003 <= stats["ink_fraction"] <= 0.55
        and stats["mean_chroma"] <= 45
    )
    working = image.convert("RGB").copy()
    if max(working.size) > max_side:
        working.thumbnail((max_side, max_side), Image.LANCZOS)
    width, height = working.size
    if width < 40 or height < 40:
        raise TraceQualityError("The source crop is too small to trace reliably.")
    gray = working.convert("L")
    histogram = gray.histogram()
    threshold = max(70, min(222, _otsu_threshold(histogram)))
    raw = gray.tobytes()

    # A one-pixel white border closes contours that touch the crop edge.
    grid_width = width + 2
    grid_height = height + 2
    grid: list[bytearray] = [bytearray(grid_width) for _ in range(grid_height)]
    for y in range(height):
        row = raw[y * width:(y + 1) * width]
        grid[y + 1][1:width + 1] = bytes(1 if value < threshold else 0 for value in row)

    segments: list[tuple[tuple[int, int], tuple[int, int]]] = []
    adjacency: dict[tuple[int, int], list[tuple[tuple[int, int], int]]] = {}

    def add_segment(first: tuple[int, int], second: tuple[int, int]) -> None:
        index = len(segments)
        segments.append((first, second))
        adjacency.setdefault(first, []).append((second, index))
        adjacency.setdefault(second, []).append((first, index))

    for y in range(grid_height - 1):
        row_top = grid[y]
        row_bottom = grid[y + 1]
        for x in range(grid_width - 1):
            a = row_top[x]
            b = row_top[x + 1]
            c = row_bottom[x + 1]
            d = row_bottom[x]
            case = a | (b << 1) | (c << 2) | (d << 3)
            if case == 0 or case == 15:
                continue
            top = (2 * x + 1, 2 * y)
            right = (2 * x + 2, 2 * y + 1)
            bottom = (2 * x + 1, 2 * y + 2)
            left = (2 * x, 2 * y + 1)
            if case == 1:
                add_segment(top, left)
            elif case == 2:
                add_segment(top, right)
            elif case == 3:
                add_segment(left, right)
            elif case == 4:
                add_segment(right, bottom)
            elif case == 5:
                add_segment(top, left)
                add_segment(right, bottom)
            elif case == 6:
                add_segment(top, bottom)
            elif case == 7:
                add_segment(left, bottom)
            elif case == 8:
                add_segment(bottom, left)
            elif case == 9:
                add_segment(top, bottom)
            elif case == 10:
                add_segment(top, right)
                add_segment(bottom, left)
            elif case == 11:
                add_segment(right, bottom)
            elif case == 12:
                add_segment(left, right)
            elif case == 13:
                add_segment(top, right)
            elif case == 14:
                add_segment(top, left)

    used = bytearray(len(segments))
    contours: list[list[tuple[float, float]]] = []
    for segment_index, (first, second) in enumerate(segments):
        if used[segment_index]:
            continue
        used[segment_index] = 1
        path = [first, second]
        previous, current = first, second
        while True:
            options = [
                (next_point, index)
                for next_point, index in adjacency.get(current, [])
                if not used[index]
            ]
            if not options:
                break
            dx, dy = current[0] - previous[0], current[1] - previous[1]
            best_point = options[0][0]
            best_index = options[0][1]
            best_score = -2.0
            for next_point, index in options:
                ex, ey = next_point[0] - current[0], next_point[1] - current[1]
                denominator = (math.hypot(dx, dy) * math.hypot(ex, ey)) or 1.0
                score = (dx * ex + dy * ey) / denominator
                if score > best_score:
                    best_score = score
                    best_point = next_point
                    best_index = index
            used[best_index] = 1
            previous, current = current, best_point
            if current == path[0]:
                break
            path.append(current)
        # Marching-squares midpoints are half a pixel away from the pixel
        # centres used by the source mask. Align them before measuring IoU.
        points = [((x / 2.0) - 0.5, (y / 2.0) - 0.5) for x, y in path]
        if len(points) > 2 and points[-1] == points[0]:
            points.pop()
        if len(points) >= 3:
            contours.append(points)

    simplified: list[list[tuple[float, float]]] = []
    total_points = 0
    for contour in contours:
        reduced = _rdp(contour, tolerance)
        if len(reduced) < 3:
            continue
        # Drop isolated single-pixel noise while keeping dots and punctuation.
        xs = [point[0] for point in reduced]
        ys = [point[1] for point in reduced]
        if (max(xs) - min(xs)) < 0.75 and (max(ys) - min(ys)) < 0.75:
            continue
        simplified.append(reduced)
        total_points += len(reduced)

    source_rows = [row[1:width + 1] for row in grid[1:height + 1]]
    structural_match = _scanline_iou(simplified, source_rows, width, height)
    path_d = _contour_path_d(simplified)
    quality = {
        "method": "trace",
        "line_art": bool(line_art),
        "background": stats["background"],
        "ink": stats["ink"],
        "contrast": stats["contrast"],
        "ink_fraction": round(stats["ink_fraction"], 4),
        "background_fraction": round(stats["background_fraction"], 4),
        "light_fraction": round(stats["background_fraction"], 4),
        "dark_fraction": round(stats["ink_fraction"], 4),
        "mean_chroma": round(stats["mean_chroma"], 2),
        "threshold": threshold,
        "width": width,
        "height": height,
        "contours": len(simplified),
        "points": total_points,
        "structural_match": round(structural_match, 4),
        "path_chars": len(path_d),
        "accepted": False,
        "reason": "",
    }
    if not line_art:
        quality["reason"] = "The source crop is not clean line art; the original crop is safer."
    elif len(simplified) < 4 or total_points < 24:
        quality["reason"] = "The source crop did not produce enough traceable structure."
    elif structural_match < 0.90:
        quality["reason"] = "The vector trace did not match the source closely enough."
    elif len(path_d) > 3_500_000:
        quality["reason"] = "The vector trace is too large to embed safely."
    else:
        quality["accepted"] = True
    quality["path_d"] = path_d
    return quality


def _decode_data_url(data_url: str) -> Image.Image:
    text = str(data_url or "")
    if not text.startswith("data:image/") or "," not in text:
        raise TraceQualityError("No saved source crop is available for tracing.")
    try:
        payload = base64.b64decode(text.split(",", 1)[1])
        return Image.open(io.BytesIO(payload)).convert("RGB")
    except Exception as exc:
        raise TraceQualityError("The saved source crop could not be decoded.") from exc


def _style_values(style: str) -> dict[str, str]:
    if str(style or "").lower() == "pencil":
        return {
            "background": "#fbf8ef",
            "ink": "#3f3f46",
            "stroke": "#52525b",
            "stroke_width": "0.45",
        }
    return {
        "background": "#ffffff",
        "ink": "#0f172a",
        "stroke": "#0f172a",
        "stroke_width": "0.32",
    }


def _svg_for_path(path_d: str, width: int, height: int, style: str) -> bytes:
    values = _style_values(style)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" shape-rendering="geometricPrecision">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="{values["background"]}"/>'
        f'<path d="{path_d}" fill="{values["ink"]}" fill-rule="evenodd" '
        f'stroke="{values["stroke"]}" stroke-width="{values["stroke_width"]}" '
        f'stroke-linejoin="round"/></svg>'
    ).encode("utf-8")


def trace_data_url(data_url: str, style: str = "color", max_side: int = 900) -> tuple[bytes, dict[str, Any]]:
    """Trace a saved JPEG/PNG data URL, with a small in-process cache."""
    key = hashlib.sha256(f"{max_side}|{data_url}".encode("utf-8")).hexdigest()
    cached = _CACHE.get(key)
    if cached is None:
        image = _decode_data_url(data_url)
        report = trace_image(image, max_side=max_side)
        if not report.get("accepted"):
            raise TraceQualityError(report.get("reason") or "The source crop could not be traced faithfully.")
        cached = {
            "path_d": report.pop("path_d"),
            "quality": report,
        }
        _CACHE[key] = cached
        _CACHE.move_to_end(key)
        while len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)
    else:
        _CACHE.move_to_end(key)
    quality = dict(cached["quality"])
    svg = _svg_for_path(cached["path_d"], int(quality["width"]), int(quality["height"]), style)
    return svg, quality
