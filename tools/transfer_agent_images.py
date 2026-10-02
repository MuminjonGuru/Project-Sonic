"""Export/verify/import private pinned agent images; never build, pull, retag or run targets."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentsec_evidence.agents.image_transfer import export_images, import_images, verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser(
        "export", help="Save exact local images to a new private directory"
    )
    export.add_argument("--output", type=Path, required=True)
    for name in ("verify", "import"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", type=Path, required=True)
        command.add_argument(
            "--manifest-sha256", required=True, help="Digest from a trusted record"
        )
        if name == "import":
            command.add_argument(
                "--output", type=Path, required=True, help="New private receipt path"
            )
    args = parser.parse_args()
    if args.command == "export":
        print(export_images(args.project_root, args.output))
    elif args.command == "verify":
        print(verify_bundle(args.bundle, args.manifest_sha256, args.project_root).model_dump_json())
    else:
        import_images(args.project_root, args.bundle, args.manifest_sha256, args.output)
        print("Image load and pinned identity checks passed; no scans were run.")


if __name__ == "__main__":
    main()
