"""
================================================================================
STRICT SESSION-LEVEL REPRODUCIBLE DATASET PARTITIONER (PHASE 3)
Department of Information Science & Engineering | Team 30
Behavioral Drift: Continuous Authentication & Honeypot Forensics
================================================================================

Implements strict, leak-free session-level partitioning:
1. Guarantees 0% window leakage across splits (all windows of a session stay together).
2. Guarantees 0% validation-test overlap (Train, Val, and Test are mutually disjoint).
3. Produces distinct manifests for:
   - Protocol A: Personalized Owner Authentication (held-out owner sessions)
   - Protocol B: Cross-User Generalization (user-disjoint test set)
   - Protocol C: Synthetic Attack Stress Testing (separate adversarial profiles)
4. Saves partitioned JSONL files and cryptographic/provenance manifests.
"""

import os
import sys
import glob
import json
import hashlib
from typing import Dict, Any, List, Tuple, Set

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SPLITS_ROOT = os.path.join(PROJECT_ROOT, "data", "splits")
EXPANDED_SESSIONS_DIR = os.path.join(PROJECT_ROOT, "data", "expanded_behavioral", "sessions")
SYNTHETIC_STRESS_DIR = os.path.join(PROJECT_ROOT, "data", "synthetic_stress")


class SessionDatasetPartitioner:
    def __init__(self, sessions_dir: str = EXPANDED_SESSIONS_DIR, splits_root: str = SPLITS_ROOT):
        self.sessions_dir = sessions_dir
        self.splits_root = splits_root
        os.makedirs(self.splits_root, exist_ok=True)

    def _load_sessions(self, directory: str) -> List[Tuple[str, List[Dict[str, Any]]]]:
        files = sorted(glob.glob(os.path.join(directory, "*.jsonl")))
        sessions = []
        for f in files:
            rows = []
            with open(f, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
            if rows:
                sessions.append((os.path.basename(f), rows))
        return sessions

    def _write_split(self, target_file: str, rows: List[Dict[str, Any]]) -> str:
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        return target_file

    def _compute_sha256(self, filepath: str) -> str:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def build_personalized_protocol(self) -> Dict[str, Any]:
        """
        Protocol A: Personalized Owner Authentication
        Evaluates continuous authentication of the enrolled owner against held-out owner
        sessions and diverse imposter sessions.
        """
        target_dir = os.path.join(self.splits_root, "personalized")
        os.makedirs(target_dir, exist_ok=True)

        all_sessions = self._load_sessions(self.sessions_dir)
        owner_sessions = [s for s in all_sessions if s[1][0].get("is_authorized", False)]
        imposter_sessions = [s for s in all_sessions if not s[1][0].get("is_authorized", False)]

        # Owner sessions: 12 total
        # Train: 8 sessions (~67%)
        # Val:   2 sessions (~17%)
        # Test:  2 sessions (~17%)
        train_owner_sess = owner_sessions[:8]
        val_owner_sess = owner_sessions[8:10]
        test_owner_sess = owner_sessions[10:]

        # Imposter sessions: 10 total across 6 identities
        # Val:   3 imposter sessions
        # Test:  7 imposter sessions (including hard negatives)
        val_imp_sess = imposter_sessions[:3]
        test_imp_sess = imposter_sessions[3:]

        # Assemble rows
        train_rows = [r for _, rows in train_owner_sess for r in rows]
        val_rows = [r for _, rows in (val_owner_sess + val_imp_sess) for r in rows]
        test_rows = [r for _, rows in (test_owner_sess + test_imp_sess) for r in rows]

        train_path = self._write_split(os.path.join(target_dir, "train_owner.jsonl"), train_rows)
        val_path = self._write_split(os.path.join(target_dir, "val_multimodal.jsonl"), val_rows)
        test_path = self._write_split(os.path.join(target_dir, "test_multimodal.jsonl"), test_rows)

        # Integrity verification: verify 0% leakage
        train_sess_ids = set(r["session_id"] for r in train_rows)
        val_sess_ids = set(r["session_id"] for r in val_rows)
        test_sess_ids = set(r["session_id"] for r in test_rows)

        assert len(train_sess_ids.intersection(val_sess_ids)) == 0, "Train and Val session overlap!"
        assert len(train_sess_ids.intersection(test_sess_ids)) == 0, "Train and Test session overlap!"
        assert len(val_sess_ids.intersection(test_sess_ids)) == 0, "Val and Test session overlap!"

        manifest = {
            "protocol_name": "Personalized_Owner_Authentication",
            "description": "Session-level disjoint splits for personalized continuous authentication.",
            "total_sessions": len(all_sessions),
            "total_windows": len(train_rows) + len(val_rows) + len(test_rows),
            "train": {
                "file": train_path,
                "sha256": self._compute_sha256(train_path),
                "samples": len(train_rows),
                "sessions": [s[0] for s in train_owner_sess],
                "authorized_samples": len(train_rows),
                "imposter_samples": 0
            },
            "validation": {
                "file": val_path,
                "sha256": self._compute_sha256(val_path),
                "samples": len(val_rows),
                "sessions": [s[0] for s in (val_owner_sess + val_imp_sess)],
                "authorized_samples": sum(1 for r in val_rows if r.get("is_authorized")),
                "imposter_samples": sum(1 for r in val_rows if not r.get("is_authorized"))
            },
            "test": {
                "file": test_path,
                "sha256": self._compute_sha256(test_path),
                "samples": len(test_rows),
                "sessions": [s[0] for s in (test_owner_sess + test_imp_sess)],
                "authorized_samples": sum(1 for r in test_rows if r.get("is_authorized")),
                "imposter_samples": sum(1 for r in test_rows if not r.get("is_authorized"))
            }
        }

        manifest_file = os.path.join(target_dir, "manifest.json")
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def build_cross_user_protocol(self) -> Dict[str, Any]:
        """
        Protocol B: Cross-User Generalization Protocol
        Test set contains users completely unseen during training or validation.
        """
        target_dir = os.path.join(self.splits_root, "cross_user")
        os.makedirs(target_dir, exist_ok=True)

        all_sessions = self._load_sessions(self.sessions_dir)
        owner_sessions = [s for s in all_sessions if s[1][0].get("is_authorized", False)]
        imposter_sessions = [s for s in all_sessions if not s[1][0].get("is_authorized", False)]

        # Train owner sessions
        train_owner_sess = owner_sessions[:9]
        val_owner_sess = owner_sessions[9:]

        # Imposter split by USER identity (user-disjoint)
        # Validation users: Imposter_Fast, Teammate_Akash
        # Test users (unseen): Imposter_Mimic_Near, Imposter_Sluggish, Imposter_RogueCLI, Teammate_Pratheek
        val_imp_users = {"Imposter_Fast", "Teammate_Akash"}
        test_imp_users = {"Imposter_Mimic_Near", "Imposter_Sluggish", "Imposter_RogueCLI", "Teammate_Pratheek"}

        val_imp_sess = [s for s in imposter_sessions if s[1][0].get("session_user_id") in val_imp_users]
        test_imp_sess = [s for s in imposter_sessions if s[1][0].get("session_user_id") in test_imp_users]

        train_rows = [r for _, rows in train_owner_sess for r in rows]
        val_rows = [r for _, rows in (val_owner_sess + val_imp_sess) for r in rows]
        test_rows = [r for _, rows in test_imp_sess for r in rows]

        train_path = self._write_split(os.path.join(target_dir, "train_owner.jsonl"), train_rows)
        val_path = self._write_split(os.path.join(target_dir, "val_multimodal.jsonl"), val_rows)
        test_path = self._write_split(os.path.join(target_dir, "test_cross_user.jsonl"), test_rows)

        manifest = {
            "protocol_name": "Cross_User_Generalization",
            "description": "User-disjoint split evaluating detection of unseen imposters.",
            "train": {
                "file": train_path,
                "sha256": self._compute_sha256(train_path),
                "samples": len(train_rows),
                "sessions": [s[0] for s in train_owner_sess]
            },
            "validation": {
                "file": val_path,
                "sha256": self._compute_sha256(val_path),
                "samples": len(val_rows),
                "users": list(set(r["session_user_id"] for r in val_rows))
            },
            "test": {
                "file": test_path,
                "sha256": self._compute_sha256(test_path),
                "samples": len(test_rows),
                "unseen_test_users": list(test_imp_users)
            }
        }

        manifest_file = os.path.join(target_dir, "manifest.json")
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def build_synthetic_stress_protocol(self) -> Dict[str, Any]:
        """
        Protocol C: Synthetic Attack Stress Testing Protocol
        Evaluates the 4 adversarial typologies completely separated from real telemetry.
        """
        target_dir = os.path.join(self.splits_root, "synthetic_stress")
        os.makedirs(target_dir, exist_ok=True)

        stress_sessions = self._load_sessions(SYNTHETIC_STRESS_DIR)
        stress_rows = [r for _, rows in stress_sessions for r in rows]

        stress_path = self._write_split(os.path.join(target_dir, "synthetic_attack_test.jsonl"), stress_rows)

        manifest = {
            "protocol_name": "Synthetic_Attack_Stress_Testing",
            "description": "Evaluates detector resilience on 4 extreme adversarial typologies.",
            "file": stress_path,
            "sha256": self._compute_sha256(stress_path),
            "total_stress_samples": len(stress_rows),
            "attack_typologies": {
                "Synthetic_Frantic": sum(1 for r in stress_rows if r.get("session_user_id") == "Synthetic_Frantic"),
                "Synthetic_Sluggish": sum(1 for r in stress_rows if r.get("session_user_id") == "Synthetic_Sluggish"),
                "Synthetic_RogueCLI": sum(1 for r in stress_rows if r.get("session_user_id") == "Synthetic_RogueCLI"),
                "Synthetic_ZeroPause": sum(1 for r in stress_rows if r.get("session_user_id") == "Synthetic_ZeroPause")
            }
        }

        manifest_file = os.path.join(target_dir, "manifest.json")
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def partition_all(self) -> Dict[str, Any]:
        pA = self.build_personalized_protocol()
        pB = self.build_cross_user_protocol()
        pC = self.build_synthetic_stress_protocol()
        print("[PARTITIONER] Successfully generated all 3 evaluation protocols with zero leakage:")
        print(f"  -> Protocol A (Personalized): Train={pA['train']['samples']}, Val={pA['validation']['samples']}, Test={pA['test']['samples']}")
        print(f"  -> Protocol B (Cross-User):   Train={pB['train']['samples']}, Val={pB['validation']['samples']}, Test={pB['test']['samples']}")
        print(f"  -> Protocol C (Stress Test):  Stress Samples={pC['total_stress_samples']}")
        return {"personalized": pA, "cross_user": pB, "synthetic_stress": pC}


if __name__ == "__main__":
    partitioner = SessionDatasetPartitioner()
    partitioner.partition_all()
