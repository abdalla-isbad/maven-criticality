#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
from pathlib import Path

def run_command(cmd, shell=False):
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        print(f"Error: {e.stderr}")
        return None

def check_python_version():
    version = sys.version_info
    if version.major != 3 or version.minor < 8:
        print(f"Error: Python 3.8+ required. Current version: {version.major}.{version.minor}")
        return False
    print(f"Python version: {version.major}.{version.minor}.{version.micro} - OK")
    return True

def create_venv():
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("Virtual environment already exists.")
        return True
    
    print("Creating virtual environment...")
    cmd = [sys.executable, "-m", "venv", "venv"]
    if run_command(cmd) is not None:
        print("Virtual environment created successfully.")
        return True
    return False

def get_activation_command():
    system = platform.system().lower()
    if system == "windows":
        return "venv\\Scripts\\activate"
    else:
        return "source venv/bin/activate"

def install_requirements():
    system = platform.system().lower()
    
    if system == "windows":
        pip_path = "venv\\Scripts\\pip.exe"
    else:
        pip_path = "venv/bin/pip"
    
    if not Path(pip_path).exists():
        print("Error: pip not found in virtual environment")
        return False
    
    print("Installing requirements...")
    cmd = [pip_path, "install", "-r", "requirements.txt"]
    if run_command(cmd) is not None:
        print("Requirements installed successfully.")
        return True
    return False

def main():
    print("=" * 50)
    print("Maven Central Criticality Analysis - Project Setup")
    print("=" * 50)
    
    if not check_python_version():
        sys.exit(1)
    
    if not create_venv():
        print("Failed to create virtual environment.")
        sys.exit(1)
    
    if not install_requirements():
        print("Failed to install requirements.")
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("Setup completed successfully!")
    print("=" * 50)
    print("\nTo start using the project:")
    print(f"1. Activate the virtual environment: {get_activation_command()}")
    print("2. Launch Jupyter: jupyter notebook")
    print("3. Open maven_central_analysis.ipynb")
    print("\nThe dataset will be downloaded automatically on first use.")

if __name__ == "__main__":
    main()