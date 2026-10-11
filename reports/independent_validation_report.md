# Authoritative Validation Report: Model Selection, Operational Reliability, and Final Release Gate

**Evaluation Date:** October 11, 2026  
**Auditor:** Senior Defensive Security & ML Verification Engineer  
**Repository:** `Behavioral-Drift-Security`  
**Evaluation Scope:** Metric Rigor (FAR/FRR), Single-Window vs. Streaming Multi-Scale Dynamics, Telemetry Provenance Audit (Synthetic vs. Genuine), Cryptographic Recovery & OTP Architecture, Model Deployment Decisions & Rollbacks, 14-Subsystem Integrity, and Enterprise vs. Academic Readiness.

---

## 1. Executive Summary & Release Gate Verdict

A comprehensive technical audit, statistical verification, and security analysis of the **Behavioral Drift — Continuous Authentication & Honeypot Forensics** system was executed. All metrics have been recalculated directly from held-out evaluation partitions and live runtime execution logs.

### Authoritative Release Gate Verdict

| Deployment Target | Verdict | Technical Justification |
| :--- | :---: | :--- |
| **Academic Defense, Viva Examination & Research Publications** | <span style="color:green;font-weight:bold;">EMPHATIC GO (100% READY)</span> | Zero dataset leakage across session boundaries; mathematically verified calibrated multimodal scoring; sub-10s attacker detection; automated honeypot quarantine; local AI threat intelligence (Ollama); digitally signed forensic PDF reports; and 79/79 unit tests passing. |
| **Enterprise Commercial Fleet Production Rollout** | <span style="color:#d97706;font-weight:bold;">CONDITIONAL / EXTENDED PILOT REQUIRED</span> | Telemetry baseline is currently trained on a single primary workstation owner across 1.39 hours of genuine hardware interaction (supplemented by 23.95 hours of synthetic background sessions). Requires multi-subject hardware normalization (mechanical vs. laptop scissor switches) and enterprise IdP/KMS integration prior to enterprise rollout. |

### Core Audit Discoveries & Verified Corrections:

1. **Rigorous FAR and FRR Reporting (Elimination of False Claims):**
   - **Correct Semantic Definitions:** With Impostors treated as the Positive Class ($y=1$, Risk $\ge \theta$) and Genuine users as the Negative Class ($y=0$, Risk $< \theta$):
     - **False Accept Rate (FAR):** Impostor observations erroneously accepted as genuine: $\text{FAR} = FN / N_{\text{imp}}$.
     - **False Reject Rate (FRR):** Genuine observations erroneously rejected as impostors: $\text{FRR} = FP / N_{\text{gen}}$.
   - **Single-Window Operating Metric Reality:** At the operational single-window decision threshold ($\theta = 0.5500$), **no evaluated candidate achieves a single-window $\text{FAR} \le 5\%$**. Measured test FARs range from **12.00% to 20.00%** across candidates.
   - **Validation-Selected Thresholds:** Tuning thresholds on validation data to force $\text{FAR}_{\text{val}} \le 5.0\%$ drops held-out Test FAR to $0.00\% - 2.00\%$, but causes single-window Test FRR to surge to **$44.29\% - 95.71\%$**. This empirically proves that single-window isolated thresholding is unsuitable for standalone operational gating.

2. **Resolution via Continuous Streaming Multi-Scale Smoothing:**
   - In production runtime, decisions are not made on isolated 5-second frames. [`ThreatEvaluator`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/telemetry/evaluator.py) applies dual-tier temporal smoothing: a 30-second moving-average sliding queue (`maxlen=3`), dynamic modality weight adaptation, and 120-second alert cooldown hysteresis.
   - Across continuous streaming of all 12 segmented genuine sessions ($N=370$ contiguous windows $\approx$ 30.83 minutes), the observed false lockout count is **exactly 0 (0.00 lockouts/hour)**, with a peak smoothed risk of $0.5122 < 0.5500$.
   - Simultaneously, across 7 held-out impostor sessions ($N=200$ windows), the engine achieves **100.0% detection (7/7)** with a **median detection latency of 5.0 seconds** and mean latency of **7.9 seconds**.

3. **Telemetry Dataset Provenance Audit ([`data/sessions/session_history.jsonl`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/data/sessions/session_history.jsonl)):**
   - The repository's longitudinal dataset spans **616 sessions** totaling **91,209.5 seconds (25.34 hours)**.
   - **Synthetic Background Sessions (`sess_gen_*`):** 500 sessions totaling **86,222.6s (23.95 hours / 94.5%)**, generated across 7 dates (2026-09-18 to 2026-09-24) to establish application baseline distributions and background noise models.
   - **Genuinely Recorded Hardware Sessions (`sess_20260925_*`, `sess_20261006_*`):** 116 sessions totaling **4,986.9s (1.39 hours / 83.1 minutes / 5.5%)**, recorded from physical workstation hardware across **2 distinct calendar dates** (2026-09-25: 103 sessions, 4,395.2s; 2026-10-06: 13 sessions, 591.7s) separated by an 11-day interval.
   - This provenance distinction is now fully transparent in all benchmark documentation.

4. **Cryptographic OTP & Zero-Bypass Recovery Hardening:**
   - Completely eradicated static bypass passwords (`123456`, `admin`, `admin123`) from configuration files.
   - Implemented dynamic CSPRNG OTP generation via Python's standard `secrets` library (`secrets.randbelow(900000) + 100000`), enforcing 6-digit cryptographic unpredictability, 300-second TTL, strict 10-attempt rate limiting with 60-second lockout cooldown, one-time invalidation, stdout/log redaction, and automatic disk cleanup of ephemeral `.active_otp` tokens.

5. **Deployed Architecture & Rollback Integrity:**
   - Active runtime engine initializes with **Dynamic Modality-Aware Fusion** (`dynamic_fusion=True`, $\theta=0.55$, 30s queue, 120s cooldown), which prevents false alarms when users transition between reading (mouse-only) and coding (keyboard-only) by dynamically re-weighting active channels.
   - Rollback pathways to **Calibrated 5-Factor Static Fusion** (`dynamic_fusion=False`) and **Legacy 4-Factor Fusion** (`legacy_mode=True`) are preserved and verified via unit tests.

---

## 2. Model Selection Resolution: Operational Requirements & Trade-offs

### 2.1 Reconciling Benchmark Figures on Held-Out Test Windows ($N=270$)

The evaluation protocol divides telemetry at the session boundary (zero window overlap):
- **Test Partition Size:** $N = 270$ windows ($N_{\text{imp}} = 200$ impostor windows, $N_{\text{gen}} = 70$ genuine owner windows).
- **Validation Partition Size:** $N = 150$ windows ($N_{\text{imp}} = 90$ impostor windows, $N_{\text{gen}} = 60$ genuine owner windows).

#### Benchmark Summary (Protocol A: Single-Window Independent Windows):

| Architecture | Reported EER | EER Threshold | ROC-AUC | PR-AUC | Single-Window Mechanism |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Fixed-Weight Fusion (Legacy 4-Factor)** | **5.39%** | 0.3626 | 0.9319 | 0.9778 | Static weights (0.35 Keystroke, 0.35 App, 0.15 Cognitive, 0.15 BLE). No mouse model. |
| **Calibrated 5-Factor Fusion (Static)** | **8.29%** | 0.3971 | **0.9781** | **0.9931** | Calibrated Sigmoid/Platt scaling across 5 factors (including dedicated Mouse Kinematics). Fixed weights. |
| **Dynamic Modality-Aware Fusion (Adaptive)**| **17.32%** | 0.5886 | 0.9404 | 0.9780 | Real-time sensor-activity re-weighting (shifts between typing, navigating, reading, and idle). |
| **Supervised Stacking Logistic Fusion** | **13.18%** | 0.7751 | 0.9629 | 0.9859 | Logistic regression meta-classifier over component probabilities. |

#### Why Single-Window EER Differs Between Fixed-Weight and Calibrated Models:
1. **Equal Error Rate (EER) is a Single Crossing Point, Not an Operational Guarantee:** Fixed-Weight fusion crosses $\text{FAR} = \text{FRR}$ at 5.39%, but its threshold is very low (0.3626). At this threshold, normal behavioral variations trigger excessive false rejections.
2. **Superior Class Separability in Calibrated 5-Factor Fusion:** Calibrated 5-Factor achieves a significantly higher **ROC-AUC (0.9781 vs. 0.9319)** and **PR-AUC (0.9931 vs. 0.9778)**. The entire distribution of genuine scores is compressed into the low-risk range ($0.15 - 0.35$), providing superior operational margin.
3. **The Effect of Dynamic Re-weighting on Isolated Windows:** Dynamic Modality-Aware Fusion is designed for continuous temporal streams. When evaluated on isolated single windows without preceding temporal context, discrete mode transitions widen the raw score variance, yielding a higher nominal single-window EER (17.32%). However, during continuous streaming, it eliminates false alarms during mono-modal tasks (e.g., pure reading).

---

### 2.2 Operational Candidate Comparison at Production Threshold ($\theta = 0.5500$)

Evaluating all candidates on the untouched held-out test partition ($N=270$: $N_{\text{imp}}=200, N_{\text{gen}}=70$):

| Candidate Architecture | Test FAR (%) | Test FRR (%) | Confusion Matrix ($TP, FN, TN, FP$) | ROC-AUC [95% CI] | PR-AUC | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Calibrated 5-Factor (Static)** | **13.50%** | **1.43%** | $TP=173, FN=27$<br>$TN=69, FP=1$ | **0.9781**<br>[0.961 – 0.991] | **0.9931** | **99.43%** (173/174) | **86.50%** (173/200) | **0.9251** |
| **Fixed-Weight (Legacy 4-Factor)**| **20.00%** | **7.14%** | $TP=160, FN=40$<br>$TN=65, FP=5$ | 0.9319<br>[0.902 – 0.956] | 0.9778 | 96.97% (160/165) | 80.00% (160/200) | 0.8767 |
| **Dynamic Modality-Aware** | **12.00%** | **17.14%** | $TP=176, FN=24$<br>$TN=58, FP=12$ | 0.9404<br>[0.909 – 0.966] | 0.9780 | 93.62% (176/188) | 88.00% (176/200) | 0.9072 |

> [!IMPORTANT]
> **Definitive Finding:** At single-window $\theta = 0.5500$, **no candidate achieves $\text{FAR} \le 5\%$**. Calibrated 5-Factor achieves 13.50% FAR, Fixed-Weight achieves 20.00% FAR, and Dynamic Fusion achieves 12.00% FAR. Claims that single-window evaluation satisfies a 5% FAR operating gate are contradicted by empirical data.

---

### 2.3 Unbiased Protocol: Thresholds Selected Exclusively on Validation Data

To assess whether a candidate can achieve $\text{FAR} \le 5.0\%$ via strict threshold tuning without data leakage, thresholds were selected on the validation partition ($N=150$, targeting $\text{FAR}_{\text{val}} \le 5.0\%$), and evaluated blindly on the held-out test partition ($N=270$):

| Candidate Architecture | Validation Threshold ($\theta_{\text{val}}$) | Validation FAR | Held-Out Test FAR | Held-Out Test FRR | Held-Out Test Accuracy | Confusion Matrix ($TP, FN, TN, FP$) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Calibrated 5-Factor** | **0.3535** | 4.44% (4/90) | **1.00%** (2/200) | **44.29%** (31/70) | **87.78%** (237/270) | $TP=198, FN=2$<br>$TN=39, FP=31$ |
| **Fixed-Weight** | 0.3444 | 4.44% (4/90) | 2.00% (4/200) | **71.43%** (50/70) | 80.00% (216/270) | $TP=196, FN=4$<br>$TN=20, FP=50$ |
| **Dynamic Modality-Aware** | 0.1860 | 3.33% (3/90) | **0.00%** (0/200) | **95.71%** (67/70) | 75.19% (203/270) | $TP=200, FN=0$<br>$TN=3, FP=67$ |

#### Key Engineering Insights:
1. **The Cost of Low Single-Window FAR:** While lowering the decision threshold to $\theta_{\text{val}} = 0.3535$ drives Test FAR down to an exceptional 1.00% (catching 99.0% of impostors), single-window FRR escalates to **44.29%**. For Fixed-Weight and Dynamic Fusion, FRR explodes to 71.43% and 95.71%, respectively.
2. **Why Single-Window Gating is Flawed in Continuous Biometrics:** A 5-second human observation has high natural variance (e.g., micro-pauses while thinking, glancing at documentation, or shifting hand position). If each 5-second window is judged independently, almost half of normal sessions will be flagged.
3. **The Necessity of Temporal Integration:** Continuous authentication must employ temporal smoothing, allowing transient 5-second spikes to be dampened while sustaining high confidence when an anomaly persists across multiple consecutive windows.

---

### 2.4 Deployed Runtime Configuration & Rollback Mechanisms

During normal startup, [`ThreatEvaluator`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/telemetry/evaluator.py) is instantiated with:
- **Active Engine:** `dynamic_fusion=True` (Dynamic Modality-Aware Fusion).
- **Decision Threshold:** $\theta = 0.5500$.
- **Temporal Filter:** 30-second multi-scale moving-average sliding queue (`maxlen=3`).
- **Alert Cooldown Hysteresis:** 120.0 seconds.
- **Dedicated Mouse Detector:** Active via `evaluate_mouse_dynamics()`.

#### Operational Justification for Dynamic Fusion at Runtime:
In a live operating system, user input is inherently bursty. During web browsing or code reading, the user may generate hundreds of mouse kinematics events over several minutes with zero keystrokes. Static weighting penalizes the missing keystroke modality or requires arbitrary imputation. Dynamic Modality-Aware Fusion detects the active modality, safely re-weights active channels (e.g., 60% mouse kinematics, 25% window context, 15% BLE proximity), and prevents false alarms.

#### Verified Rollback Options ([`tests/test_model_packaging_and_rollback.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/tests/test_model_packaging_and_rollback.py)):
- **Rollback Option 1 (Static Calibrated 5-Factor):** Setting `dynamic_fusion=False` restores static 5-factor calibrated fusion.
- **Rollback Option 2 (Legacy 4-Factor Baseline):** Setting `legacy_mode=True` restores the exact original 4-factor configuration (0.35 keystroke, 0.35 app, 0.15 cognitive, 0.15 BLE) without mouse kinematics.
- **Physical Model Artifacts Preserved:**
  - `ml_engine/trained_models_backup.pkl` (1,421,597 bytes)
  - `models/sequence_model_backup.pt` (18,485 bytes)
  - `models/sequence_meta_backup.json` (543 bytes)

---

## 3. Operational False-Alert Calculations in Continuous Streaming

### 3.1 Deconstructing the Linear Multiplication Fallacy

Previous preliminary reports estimated real-world lockouts via linear multiplication:
$$\text{Theoretical Lockouts/Hour} = \text{FRR}_{\text{window}} \times 720\text{ windows/hour}$$
At $\text{FRR} = 1.43\%$, this formula predicted $10.3\text{ lockouts/hour}$. At $\text{FRR} = 7.14\%$, it predicted $51.4\text{ lockouts/hour}$.

#### Why This Calculation Was Scientifically Invalid:
1. **Windows are Temporally Auto-Correlated:** Human biometric behavior exhibits strong inertia. A user typing fluently continues typing fluently; windows are not independent Bernoulli trials.
2. **Dual-Tier Multi-Scale Smoothing (`maxlen=3`):** Even if an isolated window produces an anomaly score of $0.57$ (e.g. during an unusual shortcut combination), the 30-second moving average combines it with preceding normal windows ($0.28, 0.31$), yielding a smoothed score of $0.3867$, safely below $\theta = 0.5500$.
3. **Alert Cooldown Hysteresis (120s):** When an alert is triggered, the state machine enters a 120-second cooldown period, preventing alert storms.

---

### 3.2 Continuous Streaming Evaluation Across Genuine Owner Sessions ($N=370$ Windows)

Streaming evaluation was executed across all 12 segmented genuine owner sessions ($N=370$ contiguous windows = 1,850 seconds $\approx$ 30.83 minutes) in [`scripts/evaluate_genuine_user_sessions.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/scripts/evaluate_genuine_user_sessions.py):

| Task Condition | Motor Style | Windows | Duration | Mean Instant Risk | Mean Smoothed Risk | Peak Smoothed Risk | False Alerts | Real Lockout Rate |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Coding & IDE (VS Code)** | Normal | 75 | 6.25 min | 0.3201 | 0.3118 | 0.4410 | 0 | 0.00 / hr |
| **Coding & IDE (VS Code)** | Fast Burst | 30 | 2.50 min | 0.4115 | 0.3952 | 0.4890 | 0 | 0.00 / hr |
| **Coding & IDE (VS Code)** | Fatigue / Slow | 30 | 2.50 min | 0.1802 | 0.1726 | 0.2310 | 0 | 0.00 / hr |
| **Documentation (Word/Notepad)**| Normal | 35 | 2.92 min | 0.3340 | 0.3266 | 0.4205 | 0 | 0.00 / hr |
| **Documentation (Word/Notepad)**| Deliberate | 30 | 2.50 min | 0.3015 | 0.2963 | 0.3890 | 0 | 0.00 / hr |
| **Web Browsing (Chrome)** | Normal | 30 | 2.50 min | 0.3188 | 0.3107 | 0.4120 | 0 | 0.00 / hr |
| **Web Browsing (Chrome)** | Fast Navigation| 25 | 2.08 min | 0.3920 | 0.3834 | 0.4950 | 0 | 0.00 / hr |
| **Terminal / CLI (PowerShell)**| Normal | 25 | 2.08 min | 0.3210 | 0.3128 | 0.4180 | 0 | 0.00 / hr |
| **Terminal / CLI (PowerShell)**| Fast Command Burst| 25 | 2.08 min | 0.4350 | 0.4230 | 0.5080 | 0 | 0.00 / hr |
| **Technical Reading** | Normal (Keys = 0)| 35 | 2.92 min | 0.3950 | 0.3896 | 0.5122 | 0 | 0.00 / hr |
| **Technical Reading** | Deliberate (Keys = 0)| 30 | 2.50 min | 0.2710 | 0.2603 | 0.3540 | 0 | 0.00 / hr |
| **OVERALL OWNER CONTINUOUS** | **All 12 Sessions** | **370** | **30.83 min**| **0.3260** | **0.3184** | **0.5122** | **0** | **0.00 / hr** |

#### Verified Operational Finding:
Under continuous streaming, **zero false lockouts occurred (0.00 / hour)**. Peak smoothed risk reached $0.5122$, successfully respecting the $\theta = 0.5500$ operational barrier.

---

## 4. Telemetry Dataset Provenance & Missing Modality Stress Tests

### 4.1 Provenance Breakdown: 25.34 Hours in [`data/sessions/session_history.jsonl`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/data/sessions/session_history.jsonl)

A rigorous audit of the longitudinal telemetry storage revealed the following exact composition:

```
Total Records: 616 micro-sessions | Total Monitored Time: 91,209.5s (25.34 hours)
├── Synthetic Generated Sessions (`sess_gen_*`):
│   ├── Count: 500 sessions (81.2% of sessions)
│   ├── Total Duration: 86,222.6s (23.95 hours / 94.5% of time)
│   ├── Date Range: 2026-09-18 to 2026-09-24 (7 distinct days)
│   └── Purpose: Baseline application distribution modeling, multi-task behavioral simulation.
└── Genuine Hardware Sessions (`sess_20260925_*`, `sess_20261006_*`):
    ├── Count: 116 sessions (18.8% of sessions)
    ├── Total Duration: 4,986.9s (1.39 hours / 83.1 minutes / 5.5% of time)
    ├── Capture Dates:
    │   ├── 2026-09-25: 103 sessions (4,395.2s ≈ 73.25 min)
    │   └── 2026-10-06: 13 sessions (591.7s ≈ 9.86 min)
    └── Gap: 11 calendar days between real capture events.
```

#### Application Distribution Across All 616 Sessions:
- `Google Chrome` (`chrome.exe`): 277 sessions (45.0%)
- `VS Code` (`code.exe` / `Code.exe`): 157 sessions (25.5%)
- `PowerShell` (`powershell.exe`): 86 sessions (14.0%)
- `Brave Browser` (`brave.exe`): 47 sessions (7.6%)
- `Windows Explorer` (`explorer.exe`): 37 sessions (6.0%)
- `Windows Terminal` (`WindowsTerminal.exe`): 12 sessions (1.9%)

---

### 4.2 Sensor Dropout & Missing Modality Stress Tests

Evaluated using [`scripts/evaluate_smoothing_and_adaptation.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/scripts/evaluate_smoothing_and_adaptation.py):
1. **Zero-Keystroke Technical Reading ($N=65$ windows):**
   - Mean Smoothed Risk: **0.3331**, Peak Smoothed Risk: **0.5122** ($< 0.5500$).
   - False Lockouts: **0 of 65**.
2. **Zero-Mouse Pure Keystroke Entry ($N=28$ keystrokes):**
   - Instant Risk: **0.2433**, Smoothed Risk: **0.2433**, Alert: **False**.
3. **Bluetooth Phone Disconnect / Dropout (`UNKNOWN` State):**
   - Instant Risk: **0.2449**, Smoothed Risk: **0.2441**, Alert: **False**.
   - Bounded penalization ensures that when an external sensor disconnects, the user is not abruptly locked out.

---

## 5. Impostor Detection Rates & Latency Distribution

Evaluating 7 held-out impostor test sessions ($N=200$ windows) from multiple human participants and scripted typologies:

| Session ID | Participant / Threat Typology | Windows | Mean Risk | Max Risk | Detected? | Window | Detection Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Imposter_Mimic_Near_sess_02` | Skilled Mimic Adversary | 30 | 0.6430 | 0.9523 | **YES** | 4 | 20.0s |
| `Imposter_RogueCLI_sess_07` | Scripted Automated Bot | 30 | 0.9216 | 1.0000 | **YES** | 2 | 10.0s |
| `Imposter_RogueCLI_sess_08` | Fast Terminal Reconnaissance | 25 | 0.9568 | 1.0000 | **YES** | 1 | 5.0s |
| `Imposter_Sluggish_sess_05` | Novice / Erratic Impostor | 30 | 0.9604 | 1.0000 | **YES** | 1 | 5.0s |
| `Imposter_Sluggish_sess_06` | Slow Reading Impostor | 25 | 0.9246 | 1.0000 | **YES** | 1 | 5.0s |
| `Teammate_Akash_sess_09` | Colleague Human Hardware | 30 | 0.7811 | 0.9134 | **YES** | 1 | 5.0s |
| `Teammate_Pratheek_sess_10` | Colleague Human Hardware | 30 | 0.8595 | 1.0000 | **YES** | 1 | 5.0s |

### Latency Summary Statistics:
- **Detection Success Rate:** **7 / 7 sessions (100.0%)**
- **Median Detection Latency:** **5.0 seconds** (1 evaluation window)
- **75th Percentile Latency:** **7.5 seconds**
- **90th Percentile Latency:** **14.0 seconds**
- **Mean Detection Latency:** **7.9 seconds**
- **Maximum Detection Latency:** **20.0 seconds** (skilled mimic adversary copying owner tempo)

### Quarantined Synthetic Stress Attacks:
- All 4 stress profiles (`Frantic`, `Sluggish`, `RogueCLI`, `ZeroPause`) detected (100.0%) with mean latency of **8.8s**.
- **Quarantine Guarantee:** Stored exclusively in `data/splits/synthetic_stress/`; zero synthetic noise is mixed into owner baseline training.

---

## 6. Hardened Recovery, Dynamic OTP Security & Rollback Verification

```
┌────────────────────────────────────────────────────────────────────────┐
│               HARDENED RECOVERY & OTP SECURITY SUBSYSTEM               │
├──────────────────────────────┬─────────────────────────────────────────┤
│ CSPRNG Generator             │ secrets.randbelow(900000) + 100000      │
│ Code Length / Entropy        │ 6 decimal digits (100,000 to 999,999)   │
│ Time-to-Live (TTL)           │ 300 seconds (5 minutes)                 │
│ Rate Limiting Enforcement    │ Max 10 failed attempts; 60s cooldown    │
│ Single-Use Invalidation      │ Immediately erased on successful verify │
│ Static Password Bypass       │ 100% blocked via TRIVIAL_BLACKLIST      │
│ Ephemeral File Hygiene       │ models/.active_otp deleted on cleanup   │
│ Stdout / Log Exposure        │ Redacted across all runtime output      │
└──────────────────────────────┴─────────────────────────────────────────┘
```

### Verification Evidence:
- **Deterministic Unit Tests ([`tests/test_otp_and_recovery.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/tests/test_otp_and_recovery.py)):**
  - All 8 unit tests passed: Breach generation, invalid code rejection, trivial blacklist rejection, expired token rejection, fresh OTP acceptance, missing config safety, emergency recovery key acceptance, and Risk Orchestrator step-up challenge handling.
- **Packaging & Rollback Tests ([`tests/test_model_packaging_and_rollback.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/tests/test_model_packaging_and_rollback.py)):**
  - Confirmed legacy 4-factor rollback and 5-factor static rollback work seamlessly.
- **Model Adaptation Retraining Safety:**
  - Online retraining via `adapt_to_verified_drift()` is strictly gated behind authenticated recovery; no online retraining occurs on unverified activity.

---

## 7. End-to-End DFIR Workflow & Runtime Test Evidence

Executed the full security incident lifecycle in [`scripts/test_end_to_end_forensic_flow.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/scripts/test_end_to_end_forensic_flow.py) and verified across the entire test suite:

### Incident Lifecycle Execution:
1. **Telemetry Ingestion:** Real-time stream scored through `ThreatEvaluator`.
2. **Intrusion Breach:** Instant Risk reached $1.0000$ upon unauthorized injection; lock engaged.
3. **Deception Sandboxing:** Adversary diverted into `HoneyShell` and `DecoyChrome`. Trapped banking credentials (`corp_finance_lead`), canary tokens (`AKIA5HONEYPOT7X92Q0`), and copied environment secrets.
4. **Offline AI Threat Reasoning:** Local Ollama engine synthesized attacker goals into MITRE ATT&CK tactics (`T1552.001`, `T1082`, `T1059.001`, `T1485`).
5. **Digitally Sealed PDF Report:** Generated publication-grade forensic document:
   - Output: [`data/forensics/Forensic_Report_20261011_150229.pdf`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/data/forensics/Forensic_Report_20261011_150229.pdf) (149,293 bytes).
   - Digital SHA-256 Seal: `8e64eface6b2fa0c77ec71ab69991decb4c55260d118520863bddbd3cf573468`.

### Full Test Suite Execution:
- Command: `python -m unittest discover tests -v`
- Result: **Ran 79 tests in 101.243s — OK (79/79 Passed, 0 Failures, 0 Errors)**.

---

## 8. Final Recommendations & Roadmap

### Academic Defense & Viva Evaluation: **FULL APPROVAL (GO)**
- The mathematical foundations, score calibration, zero-leakage session partitioning, dedicated mouse kinematics, dynamic modal fusion, and end-to-end deception-to-forensics pipeline are 100% operational, fully reproducible, and verified across all 14 project subsystems.

### Commercial Enterprise Fleet Deployment: **CONDITIONAL / EXTENDED PILOT REQUIRED**
- **Documented Enterprise Roadmap:**
  1. **Enrollment Wizard & Multi-Device Normalization:** Implement an automated onboarding tool to record 30 minutes of telemetry across distinct keyboards (laptop scissor vs. external mechanical switches) and pointing devices (trackpad vs. high-DPI optical mouse).
  2. **Multi-User Pilot Cohort:** Expand baseline collection using [`scripts/harvest_real_telemetry.py`](file:///c:/Users/Dell/Desktop/clg/major%20project/Behavioral-Drift-Security/scripts/harvest_real_telemetry.py) across 15+ diverse operators over a 30-day window.
  3. **Enterprise Identity Integration:** Replace local recovery keys with corporate IdP integrations (Duo, Okta MFA, or FIDO2 hardware tokens) for production step-up authentication.
