"""
Watermark Engine for NotesAI PDF Generation.

Adds tiled diagonal watermark to all PDF pages.
- 3 columns x 5 rows tiled pattern
- Every 2nd row shifted horizontally
- 35 degrees diagonal, light gray, ~13% opacity (12-15% range)
- Works on all page sizes (A4, Letter) and orientations (Portrait, Landscape)
- Uses Unicode font for proper apostrophe rendering
- Uses fpdf2 2.9.0 compatible methods (no save_state/set_alpha)
"""

import math
from fpdf import FPDF

# Default watermark configuration (can be overridden by app.py)
WATERMARK_TEXT = "Lucky's 59"
WATERMARK_ENABLED = True
WATERMARK_OPACITY = 0.13
WATERMARK_ANGLE = 35
WATERMARK_COLOR = (180, 180, 180)
WATERMARK_FONT_SIZE = 14
WATERMARK_COLS = 3
WATERMARK_ROWS = 5
WATERMARK_SHIFT_FACTOR = 0.5


def _draw_tiled_watermark(pdf):
    """
    Draw tiled diagonal watermark on the current page of a FPDF instance.
    Uses fpdf2 2.9.0 compatible methods.
    """
    if not WATERMARK_ENABLED:
        return

    page_width = pdf.w
    page_height = pdf.h
    margin = pdf.l_margin

    # Save graphics state
    pdf._out('q')

    # Set watermark properties
    pdf.set_font("NotesAI", size=WATERMARK_FONT_SIZE)
    pdf.set_text_color(*WATERMARK_COLOR)

    # Calculate tile dimensions
    effective_width = page_width - 2 * margin
    effective_height = page_height - 2 * margin

    col_width = effective_width / WATERMARK_COLS
    row_height = effective_height / WATERMARK_ROWS

    text_width = pdf.get_string_width(WATERMARK_TEXT)

    # Draw watermarks in a grid
    for row in range(WATERMARK_ROWS):
        for col in range(WATERMARK_COLS):
            tile_center_x = margin + col * col_width + col_width / 2
            tile_center_y = margin + row * row_height + row_height / 2

            # Shift every 2nd row
            if row % 2 == 1:
                tile_center_x += col_width * WATERMARK_SHIFT_FACTOR
                if tile_center_x > page_width - margin:
                    tile_center_x -= effective_width

            # Draw diagonal text at tile center using rotation context manager
            with pdf.rotation(WATERMARK_ANGLE, tile_center_x, tile_center_y):
                text_x = tile_center_x - text_width / 2
                text_y = tile_center_y + WATERMARK_FONT_SIZE / 3
                pdf.text(text_x, text_y, WATERMARK_TEXT)

    # Restore graphics state
    pdf._out('Q')


class WatermarkedFPDF(FPDF):
    """
    FPDF subclass that automatically adds watermarks to every page.
    """

    _watermark_enabled = WATERMARK_ENABLED

    def add_page(self, orientation="", format=(), same=False):
        """Override add_page to automatically add watermark to new page."""
        super().add_page(orientation, format, same)
        if self._watermark_enabled:
            _draw_tiled_watermark(self)

    def set_watermark(self, enabled: bool, text: str = None):
        """Enable/disable watermark and optionally change text."""
        self._watermark_enabled = enabled
        if text is not None:
            global WATERMARK_TEXT
            WATERMARK_TEXT = text


def sync_constants(text, enabled):
    """Sync constants from app.py to watermark_engine module."""
    global WATERMARK_TEXT, WATERMARK_ENABLED
    WATERMARK_TEXT = text
    WATERMARK_ENABLED = enabled
