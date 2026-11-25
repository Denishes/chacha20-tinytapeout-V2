#!/usr/bin/env python3
from pathlib import Path
import subprocess
from preset_vectors import cases

root = Path(__file__).resolve().parents[1]
build = root / "test" / "build"
build.mkdir(exist_ok=True)

vectors = list(cases())

(build / "frames.hex").write_text(
    "\n".join(frame.hex() for frame, _ in vectors) + "\n"
)
(build / "expected.hex").write_text(
    "\n".join(expected.hex() for _, expected in vectors) + "\n"
)

subprocess.run([
    "iverilog",
    "-g2012",
    "-s", "tb",
    "-Ptb.N=" + str(len(vectors)),
    "-o", str(build / "sim"),
    str(root / "src" / "chacha20_core.v"),
    str(root / "src" / "tt_um_dinis_chacha20_V2.v"),
    str(root / "test" / "tb.sv"),
], check=True)

subprocess.run(
    ["vvp", str(build / "sim")],
    cwd=build,
    check=True,
)