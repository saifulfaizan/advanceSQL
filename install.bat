@echo off
echo ========================================
echo Advanced SQL Injection Scanner Setup
echo ========================================
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

python --version
echo Python found!
echo.

echo [2/4] Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Dependencies installed successfully!
echo.

echo [3/4] Installing Playwright browsers (optional)...
set /p install_playwright="Install Playwright for JavaScript support? (y/n): "
if /i "%install_playwright%"=="y" (
    playwright install
    echo Playwright browsers installed!
) else (
    echo Skipping Playwright installation
)
echo.

echo [4/4] Creating directories...
if not exist "results" mkdir results
if not exist "logs" mkdir logs
echo Directories created!
echo.

echo ========================================
echo Installation completed successfully!
echo ========================================
echo.
echo Quick start:
echo   python main.py -u "http://example.com/page.php?id=1"
echo.
echo For help:
echo   python main.py --help
echo.
echo Examples:
echo   python examples/basic_scan.py
echo   python examples/advanced_scan.py
echo.
pause
