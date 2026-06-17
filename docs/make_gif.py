#!/usr/bin/env python3
"""
Record bash docs/_demo.sh and render the output to an animated GIF.
Uses Pillow for rendering; no display required.
"""
import re
import subprocess
import sys
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# ── config ────────────────────────────────────────────────────────────────
ROOT       = Path.cwd()
SCRIPT     = ROOT / "docs" / "_demo.sh"
OUT_GIF    = ROOT / "docs" / "demo.gif"
FONT_PATH  = r"C:\Windows\Fonts\consola.ttf"
FONT_SIZE  = 15
COLS, ROWS = 110, 34
FG         = (248, 248, 242)   # Dracula foreground
BG         = (40, 42, 54)      # Dracula background
FRAME_DUR  = 120               # ms per frame in the GIF
# ── ANSI colour map (Dracula palette) ────────────────────────────────────
ANSI_FG = {
    "30": (40,  42,  54),   # black
    "31": (255, 85, 85),    # red
    "32": (80, 250, 123),   # green
    "33": (241, 250, 140),  # yellow
    "34": (189, 147, 249),  # blue
    "35": (255, 121, 198),  # magenta
    "36": (139, 233, 253),  # cyan
    "37": (248, 248, 242),  # white
}

ANSI_RE  = re.compile(r"\x1b\[([0-9;]*)m")
STRIP_RE = re.compile(r"\x1b\[[^A-Za-z]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return STRIP_RE.sub("", text)


def parse_segments(line: str):
    """Return list of (text, fg_colour) pairs parsed from an ANSI line."""
    segments = []
    pos = 0
    cur_fg = FG
    bold = False
    for m in ANSI_RE.finditer(line):
        # plain text before this escape
        plain = line[pos:m.start()]
        if plain:
            segments.append((plain, cur_fg))
        pos = m.end()
        # parse escape codes
        codes = [c for c in m.group(1).split(";") if c]
        for code in codes:
            if code == "0" or code == "":
                cur_fg = FG
                bold = False
            elif code == "1":
                bold = True
            elif code in ANSI_FG:
                cur_fg = ANSI_FG[code]
            elif code == "39":
                cur_fg = FG
    # remainder after last escape
    tail = line[pos:]
    if tail:
        segments.append((tail, cur_fg))
    return segments


def render_frame(lines: list[str], font: ImageFont.FreeTypeFont) -> Image.Image:
    cw, ch = font.getbbox("W")[2], font.getbbox("W")[3] + 2
    W = cw * COLS + 20
    H = ch * ROWS + 20
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    for row, raw_line in enumerate(lines[:ROWS]):
        x = 10
        y = 10 + row * ch
        for text, colour in parse_segments(raw_line):
            clean = strip_ansi(text)
            if clean:
                draw.text((x, y), clean, font=font, fill=colour)
                x += cw * len(clean)
    return img


def main():
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)

    print("Running demo script…", flush=True)
    proc = subprocess.Popen(
        ["bash", "docs/_demo.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=str(ROOT),
    )

    # Collect lines with relative timestamps
    t0 = time.monotonic()
    events: list[tuple[float, str]] = []  # (time, raw_line)
    screen: list[str] = []

    for raw in proc.stdout:
        t = time.monotonic() - t0
        events.append((t, raw.rstrip("\n")))
        sys.stdout.write(raw)
        sys.stdout.flush()

    proc.wait()
    total = time.monotonic() - t0
    print(f"\nScript finished in {total:.1f}s — building GIF…", flush=True)

    # Build frames: one frame per line, replaying timing
    frames: list[Image.Image] = []
    durations: list[int] = []

    screen = []
    prev_t = 0.0

    for t, line in events:
        # hold the previous frame for the elapsed time gap
        gap_ms = int((t - prev_t) * 1000)
        if frames:
            durations[-1] = max(FRAME_DUR, gap_ms)
        prev_t = t

        # update virtual screen
        clean = strip_ansi(line)
        if clean.strip() or line.strip():
            screen.append(line)
            if len(screen) > ROWS:
                screen = screen[-ROWS:]

        img = render_frame(screen, font)
        frames.append(img)
        durations.append(FRAME_DUR)

    # hold last frame for 4 s
    if durations:
        durations[-1] = 4000

    if not frames:
        print("ERROR: no frames captured!", file=sys.stderr)
        sys.exit(1)

    frames[0].save(
        OUT_GIF,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=False,
    )
    size_kb = OUT_GIF.stat().st_size // 1024
    print(f"Saved {OUT_GIF}  ({size_kb} KB,  {len(frames)} frames)", flush=True)


if __name__ == "__main__":
    main()
