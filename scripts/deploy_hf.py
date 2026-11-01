"""Deploy the committed code (git HEAD) to a free Hugging Face Docker Space.

    uv run --with huggingface_hub python scripts/deploy_hf.py <hf-username>/vectra

One-time setup: a free account at https://huggingface.co, then `uvx --from huggingface_hub hf auth login`
with a *write* access token (https://huggingface.co/settings/tokens). The token stays in HF's local cache;
this script never reads or prints it.

Only files committed in git are uploaded (git archive HEAD), so untracked files, .env and virtualenvs
can't leak. Large cache files (>10 MB) are handled by huggingface_hub automatically.
The Space builds ./Dockerfile; the dashboard is then at https://<user>-vectra.hf.space/app
"""
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]

# Hugging Face reads the Space's settings from YAML front matter in README.md.
FRONT_MATTER = """---
title: Vectra
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
short_description: AI early warning for cyber threats (D3COY hackathon)
---

> **Live demo:** open [`/app`](./app) for the dashboard. Runs offline from cached real feeds (DEMO_MODE);
> assets and some alerts are simulated and labelled as such.

"""


def main() -> None:
    if len(sys.argv) != 2 or "/" not in sys.argv[1]:
        sys.exit("usage: python scripts/deploy_hf.py <hf-username>/<space-name>")
    space = sys.argv[1]
    if subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                      capture_output=True, text=True, check=True).stdout.strip():
        print("note: uncommitted changes are NOT deployed (only git HEAD is).")
    rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.strip()

    api = HfApi()
    print(f"logged in as {api.whoami()['name']}")
    api.create_repo(space, repo_type="space", space_sdk="docker", exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT,
                                 capture_output=True, check=True).stdout
        with tarfile.open(fileobj=BytesIO(archive)) as tar:
            tar.extractall(tmp, filter="data")
        readme = Path(tmp) / "README.md"
        readme.write_text(FRONT_MATTER + (readme.read_text(encoding="utf-8") if readme.exists() else ""),
                          encoding="utf-8")
        api.upload_folder(repo_id=space, repo_type="space", folder_path=tmp,
                          commit_message=f"Deploy {rev}", delete_patterns="*")

    user, name = space.split("/")
    print(f"uploaded {rev}. Build log: https://huggingface.co/spaces/{space}?logs=build")
    print(f"dashboard (after the build): https://{user.lower()}-{name.lower().replace('_', '-')}.hf.space/app")


if __name__ == "__main__":
    main()
