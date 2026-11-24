#!/usr/bin/env python3
"""Render 'EvanProxy Banner.html' via headless Chromium/Edge into Growtopia RTTEX assets."""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

from PIL import Image


def unpack_banner_html(html_path: Path) -> str:
    html = html_path.read_text(encoding="utf-8")
    m_tpl = re.search(r'<script type="__bundler/template">(.*?)</script>', html, re.S)
    m_man = re.search(r'<script type="__bundler/manifest">(.*?)</script>', html, re.S)
    if not m_tpl or not m_man:
        raise RuntimeError(f"Could not find bundler template/manifest in {html_path}")

    tpl: str = json.loads(m_tpl.group(1))
    manifest: dict = json.loads(m_man.group(1))

    # Inline fonts cleanly, remove external JS bundler script tag
    for uuid_key, entry in manifest.items():
        mime = entry.get("mime", "")
        raw = base64.b64decode(entry["data"])
        if entry.get("compressed"):
            raw = gzip.decompress(raw)
        if mime.startswith("font/"):
            data_url = f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
            tpl = tpl.replace(uuid_key, data_url)
        else:
            tpl = re.sub(rf'<script[^>]*src="{re.escape(uuid_key)}"[^>]*></script>', "", tpl)

    # Clean bundler/template custom tags and template vars
    tpl = tpl.replace("sc-camel-view-box=", "viewBox=")
    tpl = tpl.replace("{{accent}}", "#ffd24a")
    tpl = re.sub(r"<x-dc[^>]*>|</x-dc>|<helmet>|</helmet>|<sc-if[^>]*>|</sc-if>", "", tpl)
    tpl = re.sub(r'<script type="text/x-dc".*?</script>', "", tpl, flags=re.S)
    tpl = tpl.replace("</head>", "<style>html,body{margin:0;padding:0;background:#0d3b8e;overflow:hidden;}</style></head>")
    return tpl


def find_browser() -> Path:
    candidates = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("Neither Microsoft Edge nor Google Chrome was found.")


def encode_rttex(rgba_img: Image.Image, orig_w: int, orig_h: int) -> bytes:
    """Encode an RGBA Pillow image into Growtopia RTPACK(zlib) + RTTXTR format (bottom-up)."""
    img = rgba_img.convert("RGBA")
    w, h = img.size
    flipped = img.transpose(Image.FLIP_TOP_BOTTOM)
    pixels = flipped.tobytes("raw", "RGBA")
    mip_size = w * h * 4
    if len(pixels) != mip_size:
        raise ValueError("Unexpected RGBA pixel buffer size")

    # RTTXTR header: 124 bytes total
    header = bytearray(124)
    header[0:6] = b"RTTXTR"
    struct.pack_into("<iiiiiBBhi", header, 8, h, w, 5121, orig_h, orig_w, 1, 0, 0, 1)
    struct.pack_into("<iiiiii", header, 100, h, w, mip_size, 0, 0, 0)

    rttxtr = bytes(header) + pixels
    zdata = zlib.compress(rttxtr, 9)
    rtpack = struct.pack("<6sBBIIB15s", b"RTPACK", 0, 0, len(zdata), len(rttxtr), 1, b"\x00" * 15) + zdata
    return rtpack


def find_hero_banner_box(img: Image.Image) -> tuple[int, int, int, int]:
    """Detect the purple #3b2a6e hero banner rectangle inside the 1280px render."""
    w, h = img.size
    px = img.load()
    # Look along x=320 for pixels close to #3b2a6e (59, 42, 110) or #2a1d54/#34246a
    # Inner panel starts below header around y=110..420
    y_rows = []
    for y in range(80, min(500, h)):
        r, g, b, _ = px[120, y]
        # Inside #3b2a6e sky or its purple foreground before #0a1f38 (10, 31, 56)
        if abs(r - 59) <= 8 and abs(g - 42) <= 8 and abs(b - 110) <= 8:
            y_rows.append(y)
    if not y_rows:
        return (56, 128, 1224, 398)
    y0 = y_rows[0]
    # Hero banner height is 270px; verify bottom row where brown ground (#6b4423) meets #0a1f38
    y1 = y0 + 270
    # Adjust y1 while pixel at x=120 is NOT #0a1f38 (10, 31, 56) and within +-12px
    for probe in range(y0 + 260, min(h, y0 + 285)):
        r, g, b, _ = px[120, probe]
        if abs(r - 10) <= 5 and abs(g - 31) <= 5 and abs(b - 56) <= 5:
            y1 = probe
            break

    # Find horizontal bounds at y = y0 + 10 (hero sky #3b2a6e starts at x=56)
    probe_y = y0 + 10
    x0 = 56
    for x in range(30, 120):
        r, g, b, _ = px[x, probe_y]
        if abs(r - 59) <= 12 and abs(g - 42) <= 12 and abs(b - 110) <= 12:
            x0 = x
            break
    x1 = w - x0
    for x in range(w - 30, w - 120, -1):
        r, g, b, _ = px[x, probe_y]
        if abs(r - 59) <= 12 and abs(g - 42) <= 12 and abs(b - 110) <= 12:
            x1 = x + 1
            break
    return (x0, y0, x1, y1)


def find_cards_boxes(img: Image.Image, hero_bottom: int) -> list[tuple[int, int, int, int]]:
    """Detect the 3 rounded-white-border feature cards in the row below hero banner."""
    w, h = img.size
    px = img.load()
    # Scan vertical middle column for white top border (~#ffffff) below headline
    y_top = None
    for y in range(hero_bottom + 40, min(h, hero_bottom + 140)):
        r, g, b, _ = px[240, y]
        r2, g2, b2, _ = px[280, y]
        if r > 235 and g > 235 and b > 235 and r2 > 235 and g2 > 235 and b2 > 235:
            y_top = y
            break
    if y_top is None:
        return [
            (56, hero_bottom + 64, 431, hero_bottom + 254),
            (453, hero_bottom + 64, 828, hero_bottom + 254),
            (849, hero_bottom + 64, 1224, hero_bottom + 254),
        ]

    # Card height is 190px; locate exact bottom white border + aa edge
    y_bot = y_top + 190
    for probe in range(y_top + 185, min(h, y_top + 200)):
        r, g, b, _ = px[240, probe]
        if abs(r - 10) <= 6 and abs(g - 31) <= 6 and abs(b - 56) <= 6:
            y_bot = probe
            break

    # Detect the 3 cards reliably along the white top border row (y_top + 1)
    # Wait: corners have radius 14px, so use y_top + 14 where x starts at the exact vertical white border!
    probe_y = y_top + 14
    spans: list[tuple[int, int]] = []
    in_card = False
    cx0 = 0
    for x in range(30, w - 30):
        r, g, b, _ = px[x, probe_y]
        is_white = (r > 230 and g > 230 and b > 230)
        if is_white and not in_card:
            in_card = True
            cx0 = x
        elif in_card and (abs(r - 10) <= 8 and abs(g - 31) <= 8 and abs(b - 56) <= 8):
            if x - cx0 > 180:
                spans.append((cx0, x))
            in_card = False
    if in_card and (w - 30 - cx0 > 180):
        spans.append((cx0, w - 30))

    if len(spans) == 3:
        return [(a, y_top, b, y_bot) for (a, b) in spans]
    return [
        (56, y_top, 431, y_bot),
        (453, y_top, 828, y_bot),
        (849, y_top, 1224, y_bot),
    ]


def place_in_pot_canvas(crop: Image.Image, target_w: int, target_h: int, pot_w: int, pot_h: int, cover: bool = True) -> Image.Image:
    """Resize crop to target_w x target_h and place at top-left (0,0) on pot_w x pot_h transparent canvas."""
    cw, ch = crop.size
    if cover:
        # Fill target box cleanly without squashing aspect more than tiny trim
        scale = max(target_w / cw, target_h / ch)
        nw = max(target_w, int(round(cw * scale)))
        nh = max(target_h, int(round(ch * scale)))
        resized = crop.resize((nw, nh), Image.Resampling.LANCZOS)
        ox = (nw - target_w) // 2
        oy = (nh - target_h) // 2
        fitted = resized.crop((ox, oy, ox + target_w, oy + target_h))
    else:
        fitted = crop.resize((target_w, target_h), Image.Resampling.LANCZOS)

    canvas = Image.new("RGBA", (pot_w, pot_h), (0, 0, 0, 0))
    canvas.paste(fitted, (0, 0))
    return canvas


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    html_path = repo_root / "EvanProxy Banner.html"
    assets_dir = repo_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    preview_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if preview_dir:
        preview_dir.mkdir(parents=True, exist_ok=True)

    standalone_html = unpack_banner_html(html_path)
    browser = find_browser()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        tmp_html = tmp / "banner_standalone.html"
        tmp_png = tmp / "banner_full.png"
        tmp_html.write_text(standalone_html, encoding="utf-8")

        cmd = [
            str(browser),
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--window-size=1280,1360",
            "--force-device-scale-factor=1",
            "--hide-scrollbars",
            f"--screenshot={tmp_png}",
            tmp_html.as_uri(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0 or not tmp_png.exists():
            raise RuntimeError(f"Browser screenshot failed: rc={res.returncode}\n{res.stderr}")

        full_img = Image.open(tmp_png).convert("RGBA")

    hero_box = find_hero_banner_box(full_img)
    card_boxes = find_cards_boxes(full_img, hero_box[3])
    print(f"Detected hero_box={hero_box}, card_boxes={card_boxes}")

    hero_crop = full_img.crop(hero_box)
    # 985x256 matches Growtopia news_banner.rttex exact aspect & orig dimensions
    hero_canvas = place_in_pot_canvas(hero_crop, 985, 256, 1024, 256, cover=False)
    (assets_dir / "evanproxy_banner.rttex").write_bytes(encode_rttex(hero_canvas, 985, 256))

    card_names = ["evanproxy_card1.rttex", "evanproxy_card2.rttex", "evanproxy_card3.rttex"]
    card_crops = []
    for idx, box in enumerate(card_boxes):
        ccrop = full_img.crop(box)
        card_crops.append(ccrop)
        # Fit nicely inside 640x360 matching Growtopia 3columns_feature_btn (1024x512 POT, orig=640x360)
        # Preserve card look without vertical stretching by centering inside #0a1f38 frame or gentle fill
        c_canvas_inner = Image.new("RGBA", (640, 360), (10, 31, 56, 255))
        scale = min(620 / ccrop.width, 340 / ccrop.height)
        nw = int(round(ccrop.width * scale))
        nh = int(round(ccrop.height * scale))
        ccrop_resized = ccrop.resize((nw, nh), Image.Resampling.LANCZOS)
        c_canvas_inner.paste(ccrop_resized, ((640 - nw) // 2, (360 - nh) // 2))
        pot_card = Image.new("RGBA", (1024, 512), (0, 0, 0, 0))
        pot_card.paste(c_canvas_inner, (0, 0))
        (assets_dir / card_names[idx]).write_bytes(encode_rttex(pot_card, 640, 360))

    if preview_dir:
        full_img.crop((0, 0, 1280, 720)).save(preview_dir / "banner_rendered_top.png")
        hero_canvas.crop((0, 0, 985, 256)).save(preview_dir / "hero_985x256.png")
        for idx, cc in enumerate(card_crops):
            cc.save(preview_dir / f"card_{idx+1}.png")

    for name in ["evanproxy_banner.rttex", *card_names]:
        p = assets_dir / name
        print(f"Wrote {p} ({p.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
