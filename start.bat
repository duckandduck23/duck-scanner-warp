@echo off
title Duck Scanner
cd /d "%~dp0"
python -m pip install --quiet cryptography
python warp_web.py
pause
