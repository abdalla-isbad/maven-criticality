@echo off
REM Windows setup script for Maven Central Analysis

echo ================================================
echo Maven Central Analysis - Windows Setup
echo ================================================


python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)


python setup.py

echo.
echo Setup complete! To get started:
echo 1. Run: venv\Scripts\activate
echo 2. Run: jupyter notebook
echo 3. Open maven_central_analysis.ipynb

pause