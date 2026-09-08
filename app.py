"""
app.py (Root Entrypoint)
------------------------
Primary entry point for Streamlit Community Cloud deployment.
Configures directory paths and launches phishguard/app.py.
"""
import os
import sys
import runpy

current_file = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file)

if os.path.basename(current_dir) == "phishguard":
    PHISHGUARD_DIR = current_dir
elif os.path.isdir(os.path.join(current_dir, "phishguard")):
    PHISHGUARD_DIR = os.path.join(current_dir, "phishguard")
else:
    PHISHGUARD_DIR = current_dir

if PHISHGUARD_DIR not in sys.path:
    sys.path.insert(0, PHISHGUARD_DIR)

# Switch working directory to phishguard so relative paths (models/, sample_emails/, data/) resolve cleanly
os.chdir(PHISHGUARD_DIR)
target_app = os.path.join(PHISHGUARD_DIR, "app.py")
runpy.run_path(target_app, run_name="__main__")
