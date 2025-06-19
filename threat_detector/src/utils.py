import json
from pathlib import Path

def load_json(path):
    with open(path) as f:
        return json.load(f)

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def ensure_dirs_exist(paths):
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)
