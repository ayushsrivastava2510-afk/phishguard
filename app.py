"""
app.py (Root Entrypoint)
------------------------
Primary entry point for Streamlit Community Cloud deployment.
Configures directory paths and launches phishguard/app.py.
"""
import os
import sys
import runpy

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PHISHGUARD_DIR = os.path.join(ROOT_DIR, "phishguard")

if PHISHGUARD_DIR not in sys.path:
    sys.path.insert(0, PHISHGUARD_DIR)

# Switch working directory to phishguard so relative paths (models/, sample_emails/, data/) resolve cleanly
os.chdir(PHISHGUARD_DIR)
runpy.run_path(os.path.join(PHISHGUARD_DIR, "app.py"), run_name="__main__")
