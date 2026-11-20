#!/usr/bin/env python3
"""SVG 版面自检：在没有视觉能力的情况下，用字体度量验证文字不溢出方框、方框不互相重叠。

用法: check_svg_layout.py <file.svg>
退出码 0 = 未发现问题；1 = 有溢出或重叠。
"""
import re
import sys
import xml.etree.ElementTree as ET
from PIL import ImageFont

SVG_NS = "{http://www.w3.org/2000/svg}"
FONT_REG = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
FONT_BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"

# 与 SVG 内 <style> 中的类定义保持一致
CLASS_STYLE = {
    "title": (25, True), "sub": (14, False), "plabel": (16, True),
    "bt": (14.5, False), "bs": (12.5, False), "bm": (12.5, False),
    "nt": (12, False), "nh": (13, True), "elbl": (12.5, False),
}
PAD = 6          # 方框内边距要求
BOLD_SLACK = 1.04
_cache = {}


def measure(text, size, bold):
    key = (round(size * 2), bold)
    if key not in _cache:
        path = FONT_BOLD if bold else FONT_REG
        _cache[key] = ImageFont.truetype(path, int(round(size)), index=0)
    font = _cache[key]
    w = font.getlength(text)
    return w * (BOLD_SLACK if bold else 1.0)


def text_of(el):
    parts = [el.text or ""]
    for child in el:
        tag = child.tag.replace(SVG_NS, "")
        if tag == "tspan":
            parts.append(child.text or "")
            parts.append(child.tail or "")
        else:
            parts.append(child.tail or "")
    s = "".join(parts)
    return re.sub(r"\s+", " ", s).strip()


def style_of(el):
    cls = (el.get("class") or "").split()
    size, bold = 14.0, False
    for c in cls:
        if c in CLASS_STYLE:
            size, bold = CLASS_STYLE[c]
    fs = el.get("font-size")
    if fs:
        size = float(fs)
    fw = el.get("font-weight")
    if fw in ("700", "bold"):
        bold = True
    return size, bold


def main(path):
    raw = open(path, "rb").read()
    # 仅用于校验本仓库自己写的 SVG；仍先挡掉 DTD/实体，避免实体膨胀与外部实体解析
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        print("拒绝解析：文件含 DTD 或实体声明")
        return 2
    tree = ET.parse(path)
    root = tree.getroot()
    canvas_w = float(root.get("width"))
    canvas_h = float(root.get("height"))

    rects = []
    for r in root.iter(f"{SVG_NS}rect"):
        try:
            rects.append({
                "x": float(r.get("x")), "y": float(r.get("y")),
                "w": float(r.get("width")), "h": float(r.get("height")),
                "cls": r.get("class") or "", "rx": r.get("rx"),
            })
        except (TypeError, ValueError):
            pass

    small = [r for r in rects if r["w"] <= 1000]
    problems = []
    checked = 0

    for t in root.iter(f"{SVG_NS}text"):
        s = text_of(t)
        if not s:
            continue
        size, bold = style_of(t)
        w = measure(s, size, bold)
        x = float(t.get("x", 0))
        y = float(t.get("y", 0))
        anchor = t.get("text-anchor", "start")
        x0 = x - w / 2 if anchor == "middle" else (x - w if anchor == "end" else x)
        x1 = x0 + w
        checked += 1

        # 找最小的、垂直方向容纳该基线的方框
        cands = [r for r in rects
                 if r["y"] <= y <= r["y"] + r["h"] and r["x"] <= x <= r["x"] + r["w"]]
        if not cands:
            if x0 < 0 or x1 > canvas_w or y > canvas_h:
                problems.append(f"画布外: '{s[:44]}' x=[{x0:.0f},{x1:.0f}] y={y:.0f}")
            continue
        box = min(cands, key=lambda r: r["w"] * r["h"])
        # 阶段容器（虚线大框）不用于溢出判定，除非没有更小的框
        if box["w"] > 1000:
            inner = [r for r in cands if r["w"] <= 1000]
            if inner:
                box = min(inner, key=lambda r: r["w"] * r["h"])
            else:
                # 文字不在任何小框内（如菱形旁注）：检查它是否侵入兄弟小框
                for r in small:
                    if r["y"] <= y <= r["y"] + r["h"] and x0 < r["x"] + r["w"] - PAD and x1 > r["x"] + PAD:
                        problems.append(
                            f"侵入相邻方框({r['cls']}@{r['x']:.0f},{r['y']:.0f}): '{s[:44]}' "
                            f"x=[{x0:.0f},{x1:.0f}] 框 x=[{r['x']:.0f},{r['x'] + r['w']:.0f}]")
                continue
        if x0 < box["x"] + PAD or x1 > box["x"] + box["w"] - PAD:
            problems.append(
                f"溢出方框({box['cls'] or 'rect'} @{box['x']:.0f},{box['y']:.0f} "
                f"w={box['w']:.0f}): '{s[:52]}' 需 {w:.0f}px 可用 {box['w'] - 2 * PAD:.0f}px")

    # 小方框之间的重叠检测（忽略阶段容器与侧栏大框）
    for i in range(len(small)):
        for j in range(i + 1, len(small)):
            a, b = small[i], small[j]
            ox = min(a["x"] + a["w"], b["x"] + b["w"]) - max(a["x"], b["x"])
            oy = min(a["y"] + a["h"], b["y"] + b["h"]) - max(a["y"], b["y"])
            if ox > 2 and oy > 2:
                # 完全包含属于有意嵌套（如侧栏面板内的子框），不算重叠
                a_in_b = (a["x"] >= b["x"] and a["y"] >= b["y"]
                          and a["x"] + a["w"] <= b["x"] + b["w"]
                          and a["y"] + a["h"] <= b["y"] + b["h"])
                b_in_a = (b["x"] >= a["x"] and b["y"] >= a["y"]
                          and b["x"] + b["w"] <= a["x"] + a["w"]
                          and b["y"] + b["h"] <= a["y"] + a["h"])
                if a_in_b or b_in_a:
                    continue
                problems.append(
                    f"方框重叠 {ox:.0f}x{oy:.0f}px: ({a['cls']}@{a['x']:.0f},{a['y']:.0f}) "
                    f"与 ({b['cls']}@{b['x']:.0f},{b['y']:.0f})")

    print(f"检查文字 {checked} 段，方框 {len(rects)} 个（其中小框 {len(small)} 个）")
    if problems:
        print(f"发现 {len(problems)} 个问题：")
        for p in problems:
            print("  -", p)
        return 1
    print("未发现溢出或重叠")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/figures/projection-workflow.svg"))
