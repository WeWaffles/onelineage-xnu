#!/usr/bin/env python3
"""
Measure the stripe period of a photograph of the phone panel.

Gate B1 of DAY_SHIFT_PROMPT.md requires a *number* for every stripe claim: the
dominant spatial period, in image pixels, on both axes.  This tool produces it
from a photo without numpy or PIL - the Mac this runs on has neither, so the
decoding is `sips` (built in) plus a small pure-Python PNG reader, and the
periodicity is a plain autocorrelation.

    python3 tools/xnu/stripe_measure.py hw/photos/m301/full.jpg
    python3 tools/xnu/stripe_measure.py hw/photos/m301/*.jpg --json hw/photos/m301/measure.json

What it reports, per image:

  col.period_px  dominant period of the column-luminance profile.  Vertical
                 stripes (the panel's failure mode) appear here.
  row.period_px  same for the row profile; horizontal banding appears here.
  *.strength     normalised autocorrelation at that period, 0..1.  A clean
                 stripe pattern is >0.5; noise and flat screens are <0.2, which
                 is how "no stripes to measure" is told apart from "period 37".

Crops matter: a photo of the panel includes bezel, desk and hand.  Pass
--crop x0,y0,x1,y1 as fractions of the frame (default 0.05,0.12,0.95,0.85) to
keep only the glass.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

DEFAULT_CROP = (0.05, 0.12, 0.95, 0.85)


# ---------------------------------------------------------------- PNG reading

def _read_png(path):
    """Return (width, height, rows) where rows[y][x] = (r, g, b), 8-bit."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"{path}: not a PNG")
    pos, idat, ihdr = 8, [], None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif ctype == b"IDAT":
            idat.append(body)
        elif ctype == b"IEND":
            break
    if ihdr is None:
        raise SystemExit(f"{path}: no IHDR")
    width, height, depth, color, _comp, _filt, interlace = ihdr
    if depth != 8:
        raise SystemExit(f"{path}: bit depth {depth} unsupported (need 8)")
    if interlace:
        raise SystemExit(f"{path}: interlaced PNG unsupported")
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    if channels is None:
        raise SystemExit(f"{path}: colour type {color} unsupported")
    raw = zlib.decompress(b"".join(idat))
    stride = width * channels
    rows, prev = [], bytearray(stride)
    off = 0
    for _y in range(height):
        ftype = raw[off]
        off += 1
        line = bytearray(raw[off:off + stride])
        off += stride
        if ftype == 1:      # Sub
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:    # Average
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:    # Paeth
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        elif ftype != 0:
            raise SystemExit(f"{path}: bad filter type {ftype}")
        prev = line
        rows.append(line)
    if channels == 1:
        return width, height, [[(v, v, v) for v in r] for r in rows]
    if channels == 2:
        return width, height, [[(r[i], r[i], r[i]) for i in range(0, stride, 2)]
                               for r in rows]
    if channels == 3:
        return width, height, [[(r[i], r[i + 1], r[i + 2])
                                for i in range(0, stride, 3)] for r in rows]
    return width, height, [[(r[i], r[i + 1], r[i + 2]) for i in range(0, stride, 4)]
                           for r in rows]


def _source_size(path):
    """Original pixel size, straight from sips metadata."""
    res = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", path],
                         capture_output=True, text=True)
    w = h = None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("pixelWidth:"):
            w = int(line.split(":")[1])
        elif line.startswith("pixelHeight:"):
            h = int(line.split(":")[1])
    if not w or not h:
        raise SystemExit(f"cannot read the size of {path}: {res.stderr.strip()}")
    return w, h


def load_rgb(path, max_width=900):
    """Decode any image sips understands as (w, h, rows of RGB, scale).

    `scale` converts a measured pixel distance back to *source* pixels.  It has
    to be tracked explicitly: `sips --resampleWidth N` resamples to exactly N
    even when the source is narrower, so a 690-px image came back 900 px wide
    and every period read 1.30x too large until this was found.
    """
    src_w, src_h = _source_size(path)
    if src_w > max_width:
        width = max_width
    else:
        width = src_w
    tmpdir = tempfile.mkdtemp(prefix="stripem.")
    png = os.path.join(tmpdir, "frame.png")
    cmd = ["sips", "-s", "format", "png", "--resampleWidth", str(width),
           path, "--out", png]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 or not os.path.exists(png):
        raise SystemExit(f"sips failed on {path}: {res.stderr.strip()}")
    w, h, rows = _read_png(png)
    scale = src_w / float(w)
    return w, h, rows, scale


# ------------------------------------------------------------- periodicity

def _lum(px):
    r, g, b = px
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _profile(rows, box, axis):
    x0, y0, x1, y1 = box
    vals = []
    if axis == "col":
        for x in range(x0, x1):
            total = 0.0
            for y in range(y0, y1):
                total += _lum(rows[y][x])
            vals.append(total / (y1 - y0))
    else:
        for y in range(y0, y1):
            row = rows[y]
            total = 0.0
            for x in range(x0, x1):
                total += _lum(row[x])
            vals.append(total / (x1 - x0))
    return vals


def _detrend(vals, window=31):
    """Subtract a running mean so lighting falloff does not mask the stripes."""
    out, n = [], len(vals)
    half = max(1, window // 2)
    for i in range(n):
        lo, hi = max(0, i - half), min(n, i + half + 1)
        out.append(vals[i] - sum(vals[lo:hi]) / (hi - lo))
    return out


def _autocorr(vals):
    n = len(vals)
    mean = sum(vals) / n
    x = [v - mean for v in vals]
    energy = sum(v * v for v in x)
    if energy <= 0:
        return [0.0] * (n // 2 + 1)
    return [sum(x[i] * x[i + k] for i in range(n - k)) / energy
            for k in range(n // 2 + 1)]


def _periods(vals, min_period=3, top=5):
    ac = _autocorr(vals)
    n = len(ac)
    peaks = []
    for k in range(min_period, n - 1):
        if ac[k] > ac[k - 1] and ac[k] >= ac[k + 1]:
            peaks.append((ac[k], k))
    peaks.sort(reverse=True)
    best = []
    for strength, k in peaks[:top]:
        # parabolic refinement, so "37" means 36.6 when that is what it is
        if 0 < k < n - 1:
            denom = ac[k - 1] - 2 * ac[k] + ac[k + 1]
            delta = 0.5 * (ac[k - 1] - ac[k + 1]) / denom if denom else 0.0
        else:
            delta = 0.0
        best.append({"period_px": round(k + delta, 2),
                     "strength": round(strength, 4)})
    if not best:
        return {"period_px": None, "strength": 0.0, "peaks": []}
    return {"period_px": best[0]["period_px"],
            "strength": best[0]["strength"], "peaks": best}


def _auto_box(rows, w, h, threshold=0.22, inset=0.02):
    """Find the panel in the frame.

    A hand-held photo is mostly black bezel, desk and hand, and averaging over
    the whole frame buries the panel's structure in that black: the first
    m303 measurement reported a 19-px *row* period for a photo whose plain
    content is vertical bars, because the bars only exist inside a third of
    the frame.  The glass is the only bright region, so take the bounding box
    of the luminous pixels and measure inside it.
    """
    step_x = max(1, w // 320)
    step_y = max(1, h // 240)
    top = max(_lum(rows[y][x]) for y in range(0, h, step_y)
              for x in range(0, w, step_x))
    if top <= 1.0:
        return 0, 0, w, h
    keep = threshold * top
    xs, ys = [], []
    for x in range(0, w, step_x):
        for y in range(0, h, step_y):
            if _lum(rows[y][x]) > keep:
                xs.append(x)
                ys.append(y)
                break
    for y in range(0, h, step_y):
        for x in range(0, w, step_x):
            if _lum(rows[y][x]) > keep:
                ys.append(y)
                break
    if not xs or not ys:
        return 0, 0, w, h
    x0, x1 = min(xs), max(xs) + step_x
    y0, y1 = min(ys), max(ys) + step_y
    dx, dy = int((x1 - x0) * inset), int((y1 - y0) * inset)
    return (min(max(x0 + dx, 0), w - 16), min(max(y0 + dy, 0), h - 16),
            max(min(x1 - dx, w), x0 + 16), max(min(y1 - dy, h), y0 + 16))


def measure(path, crop=DEFAULT_CROP, max_width=900, screen_width=None):
    w, h, rows, scale = load_rgb(path, max_width=max_width)
    if crop == "auto":
        x0, y0, x1, y1 = _auto_box(rows, w, h)
    else:
        x0, y0 = int(w * crop[0]), int(h * crop[1])
        x1, y1 = int(w * crop[2]), int(h * crop[3])
    x1, y1 = min(x1, w), min(y1, h)
    if x1 - x0 < 16 or y1 - y0 < 16:
        raise SystemExit(f"{path}: crop {crop} leaves too few pixels")
    col = _periods(_detrend(_profile(rows, (x0, y0, x1, y1), "col")))
    row = _periods(_detrend(_profile(rows, (x0, y0, x1, y1), "row")))
    # Everything measured is in decoded pixels; report source pixels.
    for axis in (col, row):
        for p in axis["peaks"]:
            p["period_px"] = round(p["period_px"] * scale, 2)
        if axis["period_px"] is not None:
            axis["period_px"] = round(axis["period_px"] * scale, 2)
    result = {
        "image": path,
        "frame_px": [round(w * scale), round(h * scale)],
        "decoded_px": [w, h],
        "scale": round(scale, 4),
        "crop_px": [x0, y0, x1, y1],
        "col": col,
        "row": row,
        "verdict": _verdict(col, row),
    }
    if screen_width:
        # Scale a photo-pixel period onto the 1472-wide buffer geometry.
        glass = x1 - x0
        for axis in ("col", "row"):
            p = result[axis]["period_px"]
            if p:
                result[axis]["period_buffer_px"] = round(
                    p * float(screen_width) / glass, 2)
    return result


def _verdict(col, row):
    strong_col = col["strength"] >= 0.35
    strong_row = row["strength"] >= 0.35
    if strong_col and col["strength"] >= row["strength"]:
        return f"vertical stripes, period {col['period_px']} px " \
               f"(strength {col['strength']})"
    if strong_row:
        return f"horizontal banding, period {row['period_px']} px " \
               f"(strength {row['strength']})"
    return (f"no strong periodicity (col {col['strength']}, row "
            f"{row['strength']}) - flat, blank, or not a stripe screen")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+")
    ap.add_argument("--crop", default="auto",
                    help="'auto' to find the glass, or x0,y0,x1,y1 as "
                         "fractions of the frame")
    ap.add_argument("--max-width", type=int, default=900)
    ap.add_argument("--screen-width", type=float, default=None,
                    help="pixels across the glass in this photo, to scale the "
                         "period onto buffer pixels")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    crop = "auto" if args.crop.strip().lower() == "auto" else \
        tuple(float(v) for v in args.crop.split(","))
    out = []
    for path in args.images:
        r = measure(path, crop=crop, max_width=args.max_width,
                    screen_width=args.screen_width)
        out.append(r)
        print(f"{path}")
        print(f"  {r['verdict']}")
        for axis in ("col", "row"):
            peaks = ", ".join(f"{p['period_px']}@{p['strength']}"
                              for p in r[axis]["peaks"][:3])
            print(f"  {axis}: period={r[axis]['period_px']} "
                  f"strength={r[axis]['strength']}  peaks[{peaks}]")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(out if len(out) > 1 else out[0], f, indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
