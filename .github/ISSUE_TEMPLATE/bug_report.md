---
name: Bug report
about: Something doesn't work as described
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear and concise description of what isn't working.

**To reproduce**
Steps to reproduce the behavior, ideally with the exact settings used:
1. Config types requested (WARP / WoW / Amnezia / MASQUE / MoM / GOOL, how many of each)
2. IP stack (v4 / v6 / dual)
3. MASQUE transport (HTTP/3 or HTTP/2)
4. Whether an `xray` path was set for live testing

**What happened**
What you saw instead (log lines from the web UI or `warp_scan.py` stderr help a lot).

**Environment**
- OS (Windows / macOS / Linux, version)
- How you're running it: packaged `.exe` or `python warp_web.py` / `python warp_scan.py`
- Python version (if running from source)
- Network notes (mobile data? UDP blocked? proxy used for registration?)

**Does the generated config connect?**
If a config was produced, does it actually connect in the target app (OneXray, Xray, Hiddify, AmneziaWG, WireGuard)?
