"""
app.py (Root Entrypoint for Streamlit Community Cloud)
------------------------------------------------------
Resolves the inner 'phishguard' application package cleanly and executes it.
Contains explicit recursion guards to prevent self-invocation on Streamlit Cloud.
"""
import os
import sys
import runpy

def get_target_app():
    cwd = os.getcwd()
    # 1. If cwd has a child phishguard/app.py, target that
    child = os.path.normpath(os.path.join(cwd, "phishguard", "app.py"))
    if os.path.isfile(child):
        return child, os.path.dirname(child)

    # 2. If cwd is already the inner phishguard directory
    curr = os.path.normpath(os.path.join(cwd, "app.py"))
    parent_child = os.path.normpath(os.path.join(os.path.dirname(cwd), "phishguard", "app.py"))
    if os.path.isfile(curr) and os.path.isfile(parent_child) and curr == parent_child:
        return curr, cwd

    # 3. Fallback from __file__ location
    this_file = os.path.abspath(__file__)
    this_dir = os.path.dirname(this_file)
    candidate = os.path.normpath(os.path.join(this_dir, "phishguard", "app.py"))
    if os.path.isfile(candidate) and candidate != this_file:
        return candidate, os.path.dirname(candidate)

    if os.path.isfile(curr) and curr != this_file:
        return curr, cwd

    raise RuntimeError(f"Cannot resolve inner phishguard/app.py from CWD={cwd}")

target_app, target_dir = get_target_app()

if target_dir not in sys.path:
    sys.path.insert(0, target_dir)

# Purge stale submodule cache from sys.modules so inner module changes take effect immediately
for mod_name in list(sys.modules.keys()):
    if mod_name.startswith(("child_safety", "smishing", "quishing", "header_analysis", "origin_intel")):
        del sys.modules[mod_name]

os.chdir(target_dir)
runpy.run_path(target_app, run_name="__main__")

