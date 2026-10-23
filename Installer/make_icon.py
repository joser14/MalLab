"""Draw MalLab's shield logo (the one in the UI header) as a multi-size Windows icon.

    python make_icon.py   # writes mallab.ico next to this file
"""

from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 256
BLUE = (37, 99, 235, 255)


def shield(size: int = SIZE) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 24   # the UI's SVG uses a 24x24 viewBox: M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=size * 0.22, fill=BLUE)
    pts = [(12, 2), (4, 5), (4, 11)]
    pts += [(4 + 8 * t, 11 + 11 * t ** 1.6) for t in (0.25, 0.5, 0.75)]   # left curve down to the tip
    pts += [(12, 22)]
    pts += [(20 - 8 * t, 11 + 11 * t ** 1.6) for t in (0.75, 0.5, 0.25)]
    pts += [(20, 11), (20, 5)]
    inset = [(size * 0.5 + (x - 12) * s * 0.72, size * 0.5 + (y - 12) * s * 0.72) for x, y in pts]
    d.line(inset + [inset[0]], fill="white", width=max(2, int(size * 0.075)), joint="curve")
    return img


if __name__ == "__main__":
    out = Path(__file__).with_name("mallab.ico")
    shield().save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"wrote {out}")
