#!/bin/bash
# macOS/Linux setup script for Maven Central Analysis

echo "================================================"
echo "Maven Central Criticality Analysis - Unix Setup"
echo "================================================"

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed"
    echo "Please install Python 3.8+ using your system package manager"
    exit 1
fi

python3 setup.py

echo ""
echo "Setup complete! To get started:"
echo "1. Run: source venv/bin/activate"
echo "2. Run: jupyter notebook"  
echo "3. Open maven_central_analysis.ipynb"