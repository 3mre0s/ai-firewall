#!/usr/bin/env python3
"""
Scripted terminal-animation GIF for Local AI Firewall.
Renders a typewriter demo entirely in-process — no display, no VHS, no ttyd.

Output: docs/demo.gif
"""
from __future__ import annotations
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# ── canvas & font ─────────────────────────────────────────────────────────
FONT    = r"C:\Windows\Fonts\consola.ttf"
FSIZE   = 15
PAD     = 18          # px padding around text area
COLS    = 96          # character columns
ROWS    = 28          # character rows
OUT     = Path(__file__).parent / "demo.gif"

# ── Dracula palette ───────────────────────────────────────────────────────
BG      = (40,  42,  54)   # background
FG      = (248, 248, 242)  # foreground
YELLOW  = (241, 250, 140)  # prompt $, commands
CYAN    = (139, 233, 253)  # section headers
RED     = (255,  85,  85)  # real secrets  ← danger
GREEN   = (80,  250, 123)  # vault tokens  ← safe / success
PURPLE  = (189, 147, 249)  # banner lines
DIM     = (98,  114, 164)  # comments

# ── script: list of (action, *args) ──────────────────────────────────────
# Actions:
#   ("type",  text, colour)          — typewriter, one char / frame
#   ("line",  text, colour)          — instant full line
#   ("blank",)                       — empty line
#   ("pause", ms)                    — hold current frame
#   ("hr",    char, colour)          — full-width horizontal rule
#   ("clear",)                       — clear screen
#   ("inline", [(text,colour), ...]) — coloured segments on one line

PROMPT = [("$ ", YELLOW)]

SCRIPT = [
    # ── title ─────────────────────────────────────────────────────────────
    ("blank",),
    ("line",  "  Local AI Firewall — live demo",             CYAN),
    ("line",  "  Secrets masked before leaving your machine.", DIM),
    ("blank",),
    ("pause", 1200),

    # ── start firewall ────────────────────────────────────────────────────
    ("type",  "$ FORWARD_API_KEY=sk-ant-... ./ai-firewall",  YELLOW),
    ("pause", 400),
    ("line",  "╔══════════════════════════════════════════════╗", PURPLE),
    ("line",  "║         >>  Local AI Firewall  v0.1.0        ║", PURPLE),
    ("line",  "╠══════════════════════════════════════════════╣", PURPLE),
    ("line",  "║  Listen  :8080   │  Upstream: api.anthropic.com ║", PURPLE),
    ("line",  "║  Patterns: 28    │  Providers: 14              ║", PURPLE),
    ("line",  "╚══════════════════════════════════════════════╝", PURPLE),
    ("pause", 900),

    # ── send request with secrets ─────────────────────────────────────────
    ("blank",),
    ("type",  "$ curl localhost:8080/v1/messages \\", YELLOW),
    ("type",  "    -d '{\"messages\":[{\"role\":\"user\",\"content\":", YELLOW),
    ("type",  '         "PAT: ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ', YELLOW),
    ("type",  '          email: alice@acme-corp.com\"}]}\'', YELLOW),
    ("pause", 600),

    # ── what the provider received (KEY MOMENT) ───────────────────────────
    ("blank",),
    ("hr",    "─", CYAN),
    ("line",  "  what the AI provider received:", CYAN),
    ("hr",    "─", CYAN),
    ("line",  "  {", FG),
    ("line",  '    "messages": [{', FG),
    ("line",  '      "role": "user",', FG),
    ("line",  '      "content": "PAT: ', FG),
    ("inline", [
        ('        ', FG),
        ('[[GH_PAT_F1B7B69D]]', GREEN),
        ('   ← secret replaced by vault token', DIM),
    ]),
    ("inline", [
        ('        email: ', FG),
        ('[[EMAIL_73AB1869]]', GREEN),
        ('       ← PII replaced', DIM),
    ]),
    ("line",  '    }]', FG),
    ("line",  '  }', FG),
    ("pause", 2800),   # ← hold here so reader can see the masked output

    # ── response: secrets restored ────────────────────────────────────────
    ("blank",),
    ("hr",    "─", CYAN),
    ("line",  "  client response (secrets restored by firewall):", CYAN),
    ("hr",    "─", CYAN),
    ("inline", [
        ('  "content": "PAT: ', FG),
        ('ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ', RED),
        ('  ← restored', DIM),
    ]),
    ("inline", [
        ('             email: ', FG),
        ('alice@acme-corp.com', RED),
        ('                 ← restored', DIM),
    ]),
    ("blank",),
    ("line",  "  [OK]  Provider never saw plaintext — only vault tokens.", GREEN),
    ("line",  "  [OK]  Originals restored in the response automatically.", GREEN),
    ("pause", 4000),  # ← final hold before loop
]

# ─────────────────────────────────────────────────────────────────────────

def build_frames(font: ImageFont.FreeTypeFont):
    bbox = font.getbbox("W")
    cw   = bbox[2]          # character width
    ch   = bbox[3] + 3      # character height + leading
    W    = cw * COLS + PAD * 2
    H    = ch * ROWS + PAD * 2

    frames: list[Image.Image] = []
    durations: list[int] = []
    lines: list[list[tuple[str, tuple]]] = [[]]  # list of rows; each row = [(text, colour)]

    def snapshot(hold_ms: int = 100):
        img  = Image.new("RGB", (W, H), BG)
        draw = ImageDraw.Draw(img)
        for r, row in enumerate(lines[-ROWS:]):
            x = PAD
            y = PAD + r * ch
            for text, colour in row:
                draw.text((x, y), text, font=font, fill=colour)
                x += cw * len(text)
        frames.append(img)
        durations.append(hold_ms)

    def newline():
        lines.append([])

    def append_text(text: str, colour: tuple):
        if not lines:
            lines.append([])
        lines[-1].append((text, colour))

    for action in SCRIPT:
        op = action[0]

        if op == "blank":
            newline()
            snapshot(80)

        elif op == "pause":
            if frames:
                durations[-1] += action[1]
            else:
                newline(); snapshot(action[1])

        elif op == "clear":
            lines.clear(); lines.append([])
            snapshot(100)

        elif op == "hr":
            _, char, colour = action
            append_text(char * COLS, colour)
            snapshot(60)
            newline()

        elif op == "line":
            _, text, colour = action
            append_text(text, colour)
            snapshot(80)
            newline()

        elif op == "inline":
            _, segments = action
            for text, colour in segments:
                append_text(text, colour)
            snapshot(80)
            newline()

        elif op == "type":
            _, text, colour = action
            # emit 2 chars per frame → half the frames, same apparent speed
            for i in range(0, len(text), 2):
                chunk = text[i:i+2]
                append_text(chunk, colour)
                snapshot(55)          # ~36 chars/second at 2 chars/frame
            snapshot(120)             # brief pause at end of line
            newline()

    return frames, durations


def main():
    print("Building scripted demo GIF…", flush=True)
    font = ImageFont.truetype(FONT, FSIZE)
    frames, durations = build_frames(font)

    print(f"  {len(frames)} frames — saving…", flush=True)
    # Quantize to 64-colour palette — GIF native, cuts file size ~3×
    palette_frames = [f.quantize(colors=64, method=Image.Quantize.FASTOCTREE) for f in frames]
    palette_frames[0].save(
        OUT,
        save_all=True,
        append_images=palette_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    kb = OUT.stat().st_size // 1024
    print(f"  Saved {OUT}  ({kb} KB)", flush=True)


if __name__ == "__main__":
    main()
