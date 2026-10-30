"""Publish the fine-tuned Llama Guard adapter to Hugging Face (run by the repository owner, with their own token).

    uv run python scripts/publish_lg_adapter.py                       # dry run: download and list what would be uploaded
    uv run python scripts/publish_lg_adapter.py --publish             # upload (needs HF_TOKEN with write access)

The adapter files come from the Modal volume (models/llamaguard1b-gatekeeper-v2); the model card is
docs/hf-model-card.md. The Llama 3.2 license requires derivative model names to start with "Llama".
"""

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOLUME_DIR = "models/llamaguard1b-gatekeeper-v2"
FILES = ("adapter_config.json", "adapter_model.safetensors", "threshold.json", "tokenizer.json", "tokenizer_config.json",
         "special_tokens_map.json")
DEFAULT_REPO = "lbaumberger/Llama-Guard-3-1B-Gatekeeper-npm"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--publish", action="store_true", help="actually create the repo and upload")
    args = ap.parse_args()
    if not args.repo.split("/")[-1].startswith("Llama"):
        raise SystemExit("Llama 3.2 license: the model name must start with 'Llama'")

    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        for name in FILES:
            subprocess.run(["modal", "volume", "get", "--force", "gatekeeper-data", f"{VOLUME_DIR}/{name}", str(out / name)],
                           check=True, capture_output=True)
        shutil.copy(ROOT / "docs" / "hf-model-card.md", out / "README.md")
        for p in sorted(out.iterdir()):
            print(f"{p.name:32} {p.stat().st_size:>12,} bytes")
        if not args.publish:
            print(f"\ndry run: nothing uploaded. Re-run with --publish to create https://huggingface.co/{args.repo}")
            return
        from huggingface_hub import HfApi

        api = HfApi()  # token from HF_TOKEN or `huggingface-cli login`
        api.create_repo(args.repo, repo_type="model", exist_ok=True)
        api.upload_folder(folder_path=str(out), repo_id=args.repo, repo_type="model",
                          commit_message="Gatekeeper Llama Guard 3 1B adapter (v2)")
        print(f"published: https://huggingface.co/{args.repo}")


if __name__ == "__main__":
    main()
