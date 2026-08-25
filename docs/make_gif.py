#!/usr/bin/env python3
"""Capture and render the production demo as an approximately 60-second GIF."""

import argparse
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent
OUTPUT = ROOT / "demo.gif"
CAPTURE = ROOT / "demo-output.txt"
FONT_PATHS = (
    Path(r"C:\Windows\Fonts\consola.ttf"),
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    Path("/System/Library/Fonts/Menlo.ttc"),
)

BACKGROUND = (13, 17, 23)
FOREGROUND = (230, 237, 243)
DIM = (139, 148, 158)
CYAN = (88, 166, 255)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in FONT_PATHS:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise SystemExit("No supported monospace font found")


def colour(line: str) -> tuple[int, int, int]:
    if line.startswith("$"):
        return CYAN
    if line.startswith("[DETECTED]"):
        return YELLOW
    if line.startswith(("[MASKED]", "[UPSTREAM]", "[STREAM]", "[RESULT]")):
        return GREEN
    return FOREGROUND


def capture_demo() -> None:
    result = subprocess.run(
        ["go", "run", ".", "demo", "--non-interactive"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    CAPTURE.write_text(
        "$ anonmyz demo --non-interactive\n\n" + result.stdout.strip() + "\n",
        encoding="utf-8",
    )


def render() -> None:
    lines = CAPTURE.read_text(encoding="utf-8").splitlines()
    font = load_font(22)
    title_font = load_font(24)
    width, height = 1280, 720
    line_height = 34
    frames: list[Image.Image] = []
    durations: list[int] = []

    def frame(visible: int, status: str, duration: int) -> None:
        image = Image.new("RGB", (width, height), BACKGROUND)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((28, 24, width - 28, height - 24), radius=16, outline=(48, 54, 61), width=2)
        draw.ellipse((52, 48, 68, 64), fill=(248, 81, 73))
        draw.ellipse((78, 48, 94, 64), fill=(210, 153, 34))
        draw.ellipse((104, 48, 120, 64), fill=GREEN)
        draw.text((148, 42), "Anonmyz — local-first AI privacy", font=title_font, fill=FOREGROUND)
        draw.text((54, 94), "Real production-path demo · no API key · loopback only", font=font, fill=DIM)

        y = 152
        for line in lines[:visible]:
            draw.text((58, y), line, font=font, fill=colour(line))
            y += line_height

        draw.text((58, height - 72), status, font=font, fill=DIM)
        frames.append(image)
        durations.append(duration)

    frame(0, "Starting the local deterministic demo…", 2500)
    for index in range(1, len(lines) + 1):
        line = lines[index - 1]
        hold = 2600 if line.startswith(("[UPSTREAM]", "[STREAM]")) else 1500
        frame(index, "Mask locally → send placeholders → restore locally", hold)
    frame(len(lines), "Done: four sensitive values never left this machine in plaintext.", 35000)

    palette = [item.quantize(colors=64, method=Image.Quantize.FASTOCTREE) for item in frames]
    palette[0].save(
        OUTPUT,
        save_all=True,
        append_images=palette[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"Rendered {OUTPUT} ({sum(durations) / 1000:.1f}s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", action="store_true", help="run the real demo before rendering")
    arguments = parser.parse_args()
    if arguments.capture:
        capture_demo()
    render()
