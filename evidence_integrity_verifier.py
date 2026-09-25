#!/usr/bin/env python3
"""Create and verify SHA-256 manifests for audit evidence."""

import hashlib
import json
import logging
import os
import sys
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("EvidenceVerifier")


def calculate_sha256(filepath):
    digest = hashlib.sha256()
    try:
        with open(filepath, "rb") as evidence:
            for block in iter(lambda: evidence.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as error:
        logger.error("Error reading file '%s': %s", filepath, error)
        return None


class EvidenceIntegrityManager:
    def __init__(self, target_directory="."):
        self.directory = os.path.abspath(target_directory)
        self.manifest_path = os.path.join(self.directory, "evidence_integrity_manifest.json")

    def generate_manifest(self, evidence_files=None):
        if evidence_files is None:
            evidence_files = [
                os.path.join(root, name)
                for root, _, names in os.walk(self.directory)
                for name in names
                if name != os.path.basename(self.manifest_path) and not name.endswith(".py")
            ]
        inventory = []
        for path in evidence_files:
            file_hash = calculate_sha256(path)
            if file_hash:
                inventory.append({
                    "file_name": os.path.basename(path),
                    "relative_path": os.path.relpath(path, self.directory),
                    "sha256_hash": file_hash,
                    "size_bytes": os.path.getsize(path),
                    "last_modified": datetime.utcfromtimestamp(os.path.getmtime(path)).isoformat() + "Z",
                })
        manifest = {"metadata": {"generated_at": datetime.utcnow().isoformat() + "Z", "hash_algorithm": "SHA-256"}, "evidence_inventory": inventory}
        with open(self.manifest_path, "w", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2)
        return manifest

    def verify_manifest(self):
        if not os.path.exists(self.manifest_path):
            logger.error("Manifest file '%s' does not exist.", self.manifest_path)
            return False
        with open(self.manifest_path, encoding="utf-8") as source:
            manifest = json.load(source)
        passed = True
        for item in manifest["evidence_inventory"]:
            path = os.path.join(self.directory, item["relative_path"])
            if not os.path.exists(path) or calculate_sha256(path) != item["sha256_hash"]:
                logger.error("[FAILED] %s", item["relative_path"])
                passed = False
        print("Overall Integrity Status:", "PASSED (COMPLIANT)" if passed else "FAILED")
        return passed


if __name__ == "__main__":
    manager = EvidenceIntegrityManager()
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        raise SystemExit(0 if manager.verify_manifest() else 1)
    manager.generate_manifest()
