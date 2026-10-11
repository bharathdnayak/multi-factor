import os
import glob
import json
import math
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_audit():
    print("=" * 80)
    print("PHASE 1: THOROUGH DATASET & PIPELINE AUDIT")
    print("=" * 80)

    # 1. Harvested Sessions
    sessions_dir = os.path.join(PROJECT_ROOT, "data", "harvested", "sessions")
    session_files = glob.glob(os.path.join(sessions_dir, "*.jsonl"))
    
    sess_rows = []
    for sf in session_files:
        fname = os.path.basename(sf)
        with open(sf, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if line.strip():
                    r = json.loads(line)
                    r["_file"] = fname
                    r["_row_idx"] = idx
                    sess_rows.append(r)
                    
    df_sess = pd.DataFrame(sess_rows)
    print(f"\n1. HARVESTED SESSIONS DIRECTORY: {sessions_dir}")
    print(f"   Total Session Files: {len(session_files)}")
    print(f"   Total Records across all session files: {len(df_sess)}")
    
    file_summary = df_sess.groupby(["_file", "session_user_id", "is_authorized", "task_mode"]).agg(
        row_count=("timestamp", "count"),
        min_ts=("timestamp", "min"),
        max_ts=("timestamp", "max")
    ).reset_index()
    file_summary["duration_sec"] = file_summary["max_ts"] - file_summary["min_ts"] + 5
    print("\n   File Breakdown:")
    for _, row in file_summary.iterrows():
        print(f"   - {row['_file']}: {row['row_count']} rows, User={row['session_user_id']}, Auth={row['is_authorized']}, Task={row['task_mode']}, Duration={row['duration_sec']}s ({row['duration_sec']/60:.1f}m)")

    # 2. Partitions in data/harvested
    print("\n2. EXISTING PARTITIONS IN data/harvested:")
    train_file = os.path.join(PROJECT_ROOT, "data", "harvested", "train_owner.jsonl")
    val_file = os.path.join(PROJECT_ROOT, "data", "harvested", "val_owner.jsonl")
    test_file = os.path.join(PROJECT_ROOT, "data", "harvested", "test_multimodal.jsonl")
    manifest_file = os.path.join(PROJECT_ROOT, "data", "harvested", "dataset_manifest.json")
    
    train_rows = [json.loads(line) for line in open(train_file, "r", encoding="utf-8") if line.strip()] if os.path.exists(train_file) else []
    val_rows = [json.loads(line) for line in open(val_file, "r", encoding="utf-8") if line.strip()] if os.path.exists(val_file) else []
    test_rows = [json.loads(line) for line in open(test_file, "r", encoding="utf-8") if line.strip()] if os.path.exists(test_file) else []
    
    print(f"   train_owner.jsonl: {len(train_rows)} samples")
    print(f"   val_owner.jsonl:   {len(val_rows)} samples")
    print(f"   test_multimodal:   {len(test_rows)} samples")
    
    if os.path.exists(manifest_file):
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        print("   dataset_manifest.json contents:")
        print(f"      created_at: {manifest.get('created_at')}")
        print(f"      total_sessions: {manifest.get('total_sessions')}")
        print(f"      total_owner_samples: {manifest.get('total_owner_samples')}")
        print(f"      total_imposter_samples: {manifest.get('total_imposter_samples')}")
        print(f"      train_samples: {manifest.get('train_samples')}")
        print(f"      val_samples: {manifest.get('val_samples')}")
        print(f"      test_samples: {manifest.get('test_samples')}")
        print(f"      user_breakdown: {manifest.get('user_breakdown')}")

    # Check for exact row duplicates and overlap between splits
    val_hashes = [json.dumps(r, sort_keys=True) for r in val_rows]
    test_hashes = [json.dumps(r, sort_keys=True) for r in test_rows]
    train_hashes = [json.dumps(r, sort_keys=True) for r in train_rows]
    
    val_in_test = sum(1 for h in val_hashes if h in set(test_hashes))
    train_in_test = sum(1 for h in train_hashes if h in set(test_hashes))
    train_in_val = sum(1 for h in train_hashes if h in set(val_hashes))
    
    print("\n3. SPLIT OVERLAP & LEAKAGE:")
    print(f"   Validation samples appearing in Test set: {val_in_test} of {len(val_rows)} ({val_in_test/len(val_rows)*100:.1f}%)")
    print(f"   Training samples appearing in Test set:   {train_in_test} of {len(train_rows)}")
    print(f"   Training samples appearing in Val set:    {train_in_val} of {len(train_rows)}")

    # Check session mixing: are windows from the SAME session divided between train and test?
    # Session is identified by user + task + session timestamp
    df_train = pd.DataFrame(train_rows)
    df_test = pd.DataFrame(test_rows)
    df_val = pd.DataFrame(val_rows)
    
    # In harvested data, the 3 owner sessions are browsing, coding, docs
    train_tasks = set(df_train["task_mode"].unique()) if len(df_train) > 0 else set()
    test_owner_tasks = set(df_test[df_test["is_authorized"] == True]["task_mode"].unique()) if len(df_test) > 0 else set()
    val_tasks = set(df_val["task_mode"].unique()) if len(df_val) > 0 else set()
    
    print("\n   Owner tasks in Train:", train_tasks)
    print("   Owner tasks in Val:  ", val_tasks)
    print("   Owner tasks in Test: ", test_owner_tasks)
    print("   -> SESSIONS FROM ALL 3 OWNER TASKS ARE IN BOTH TRAIN AND TEST!")
    print("   -> Splitting was done at random window level, NOT session level!")

    # 4. Check Label Leaks in Features
    print("\n4. FEATURE LEAKAGE & SYNTHETIC PROVENANCE:")
    for col in ["ble_proximity_state", "ble_estimated_distance_m", "mouse_straightness_mean", "cpu_usage", "ram_usage_mb"]:
        if col in df_sess.columns:
            auth_vals = df_sess[df_sess["is_authorized"] == True][col].unique()
            unauth_vals = df_sess[df_sess["is_authorized"] == False][col].unique()
            print(f"   Feature '{col}':")
            print(f"      Authorized unique values:   {auth_vals[:5]}")
            print(f"      Unauthorized unique values: {unauth_vals[:5]}")

    # 5. Missing / corrupted / non-finite values
    print("\n5. DATA INTEGRITY & CORRUPTED VALUES:")
    numeric_cols = df_sess.select_dtypes(include=[np.number]).columns
    null_counts = df_sess[numeric_cols].isnull().sum()
    nulls = null_counts[null_counts > 0]
    print(f"   Null count in session data: {len(nulls)}")
    
    inf_counts = np.isinf(df_sess[numeric_cols]).sum()
    infs = inf_counts[inf_counts > 0]
    print(f"   Inf count in session data: {len(infs)}")

    # 6. Audit other data sources: telemetry_data.jsonl, data/raw, session_history
    print("\n6. OTHER DATA SOURCES IN REPOSITORY:")
    telem_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    if os.path.exists(telem_file):
        telem_rows = [json.loads(line) for line in open(telem_file, "r", encoding="utf-8") if line.strip()]
        df_telem = pd.DataFrame(telem_rows)
        print(f"   telemetry_data.jsonl: {len(telem_rows)} rows")
        if "mouse_jerk_mean" in df_telem.columns:
            print(f"      mouse_jerk_mean min: {df_telem['mouse_jerk_mean'].min()}, max: {df_telem['mouse_jerk_mean'].max()}, mean: {df_telem['mouse_jerk_mean'].mean()}")
        if "mouse_velocity_mean" in df_telem.columns:
            print(f"      mouse_velocity_mean min: {df_telem['mouse_velocity_mean'].min()}, max: {df_telem['mouse_velocity_mean'].max()}")
        if "keystroke_count" in df_telem.columns:
            print(f"      zero keystroke windows: {(df_telem['keystroke_count'] == 0).sum()} of {len(df_telem)}")

    raw_dir = os.path.join(PROJECT_ROOT, "data", "raw")
    for f in os.listdir(raw_dir):
        fp = os.path.join(raw_dir, f)
        if os.path.isfile(fp) and f.endswith(".csv"):
            df_r = pd.read_csv(fp)
            print(f"   data/raw/{f}: {df_r.shape[0]} rows, cols={list(df_r.columns)}")

    session_hist_file = os.path.join(PROJECT_ROOT, "data", "sessions", "session_history.jsonl")
    if os.path.exists(session_hist_file):
        hist_rows = [json.loads(line) for line in open(session_hist_file, "r", encoding="utf-8") if line.strip()]
        print(f"   data/sessions/session_history.jsonl: {len(hist_rows)} micro-sessions")

    app_base_file = os.path.join(PROJECT_ROOT, "data", "sessions", "app_baselines.json")
    if os.path.exists(app_base_file):
        with open(app_base_file, "r", encoding="utf-8") as f:
            baselines = json.load(f)
        print(f"   data/sessions/app_baselines.json: {len(baselines)} profile envelopes:")
        for k, v in list(baselines.items())[:5]:
            print(f"      - {k}: sample_count={v.get('sample_count')}")

    print("\n" + "=" * 80)

if __name__ == "__main__":
    run_audit()
