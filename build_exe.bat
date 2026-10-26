@echo off
title Build Duck Scanner
cd /d "%~dp0"
python -m pip install --quiet pyinstaller cryptography
pyinstaller --noconfirm Duck-Scanner.spec
if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)
echo.
echo Built: dist\Duck-Scanner.exe
pause
