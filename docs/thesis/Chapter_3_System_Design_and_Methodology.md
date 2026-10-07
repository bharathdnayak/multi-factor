# CHAPTER 3: SYSTEM DESIGN AND METHODOLOGY

## 3.1 Architectural Philosophy and System Design
The proposed architecture is engineered around the principle of **Multi-Factor Continuous Assessment with Active Deceptive Containment**. The system operates transparently across five coordinated functional stages:
1. **Stage 1: Multi-Modal Continuous Sensing:** Passively collects physical keyboard/mouse kinematics, intra-app cognitive context, and environmental BLE proximity.
2. **Stage 2: Quad-Factor Fusion & Online Drift Detection:** Fuses 1D-CNN Deep SVDD, OC-SVM, Isolation Forest, and AI Cognitive models while running ADWIN Hoeffding-bound drift tests.
3. **Stage 3: 3-Tier Dynamic Risk Orchestration:** Enforces graduated intervention based on instantaneous and smoothed Bayesian threat risk.
4. **Stage 4: 1:1 Sandboxed Deception Honeypot:** Seamlessly diverts verified intruders into an emulated Windows desktop equipped with honey-tokens and C2 interception.
5. **Stage 5: Offline AI Forensics & Custody Reporting:** Employs local LLM threat intelligence to compile multi-page executive PDF reports with SHA-256 digital evidence chains.

```
+─────────────────────────────────────────────────────────────────────────────+
|                          END-TO-END SYSTEM PIPELINE                         |
+─────────────────────────────────────────────────────────────────────────────+
  [User Input Peripherals & BLE Device]
                 │
                 ▼
  [Stage 1: Multi-Modal Telemetry Acquisition (telemetry/agent.py)]
                 │  (10-second window streaming)
                 ▼
  [Stage 2: Quad-Factor Fusion & ADWIN Drift Daemon (telemetry/evaluator.py)]
      ├── Deep SVDD 1D-CNN Keystroke Embedding (Weight: 0.35)
      ├── Biometric One-Class SVM Dynamics (Weight: 0.35)
      ├── Contextual Isolation Forest (Weight: 0.15)
      ├── AI Cognitive Task Controller (Weight: 0.15)
      └── Environmental BLE Path Loss Penalty (+0.25 on walk-away)
                 │
                 ▼
  [Stage 3: 3-Tier Dynamic Risk Orchestrator (security/risk_orchestrator.py)]
      ├── Tier 1 (Risk < 0.40): Silent Background Monitoring
      ├── Tier 2 (0.40 <= Risk <= 0.75): Non-Blocking Step-Up Toast Challenge
      └── Tier 3 (Risk > 0.75): Fullscreen Lockdown & Silent Webcam Snapshot
                 │  (On 3 failed OTPs or "Bypass Prompt" click)
                 ▼
  [Stage 4: 1:1 Sandboxed Deception Honeypot (deception/honey_desktop.py)]
      ├── Decoy Chrome: Corporate NetBanking Trap & AWS IAM Root Honey-Tokens
      ├── HoneyShell: Network Discovery Traps (ping, arp, route, whoami)
      └── C2 Malware Interception: Diverted into data/sandbox/
                 │  (On recovery hotkey Ctrl+Alt+Shift+U + 'admin'/OTP)
                 ▼
  [Stage 5: Offline AI Forensics & Legal PDF Generation (dashboard/pdf_generator.py)]
      ├── Local Offline Ollama (qwen2.5:3b) MITRE ATT&CK Classification
      └── Executive Multi-Page Forensic PDF Report Export
```


![Figure 3.1: High-Resolution System Architecture Diagram](../assets/architecture_diagram.png)
*Figure 3.1: High-Resolution Architectural Overview of the Multi-Factor Continuous Authentication and Deception Framework.*

![Figure 3.2: Procedural Workflow and Inter-Module Communication Pipeline](../assets/end_to_end_structure.png)
*Figure 3.2: Procedural Workflow and Inter-Module Communication Pipeline.*
## 3.2 Mathematical Formulation of Telemetry and Environmental Sensing
### 3.2.1 Keystroke Dynamics Formulation
For each active 10-second observation window containing $K$ keystroke events, the system computes the feature vector:
$$\mathbf{f}_{key} = [\mu(T_d), \sigma(T_d), \mu(T_f), \sigma(T_f), R_{bksp}, R_{spec}, R_{pause}]^T$$
where:
* $\mu(T_d)$ and $\sigma(T_d)$ are the empirical mean and standard deviation of dwell times.
* $\mu(T_f)$ and $\sigma(T_f)$ are the empirical mean and standard deviation of flight times.
* $R_{bksp} = \frac{N_{backspace}}{K}$ is the backspace correction ratio.
* $R_{spec} = \frac{N_{modifier}}{K}$ is the ratio of modifier shortcuts (Ctrl, Alt, Shift).
* $R_{pause} = \frac{N(T_f > 1.5s)}{K}$ is the reading/thinking pause ratio.

### 3.2.2 Mouse Kinematics Formulation
For a discrete sequence of cursor coordinate samples $P = \{(x_i, y_i, t_i)\}_{i=1}^M$, the kinematic features are computed as:
* **Instantaneous Velocity:**
  $$v_i = \frac{\sqrt{(x_i - x_{i-1})^2 + (y_i - y_{i-1})^2}}{t_i - t_{i-1}}$$
* **Instantaneous Acceleration:**
  $$a_i = \frac{v_i - v_{i-1}}{t_i - t_{i-1}}$$
* **Instantaneous Jerk (Tremor Indicator):**
  $$j_i = \frac{a_i - a_{i-1}}{t_i - t_{i-1}}$$
* **Trajectory Straightness Ratio:**
  $$S = \frac{\sqrt{(x_M - x_1)^2 + (y_M - y_1)^2}}{\sum_{i=2}^M \sqrt{(x_i - x_{i-1})^2 + (y_i - y_{i-1})^2}}$$

### 3.2.3 Environmental BLE Proximity Path Loss Model
Workstation distance to the owner's smartphone is estimated using the Log-Distance Path Loss Model:
$$RSSI(d) = RSSI_0 - 10n \log_{10}\left(\frac{d}{d_0}\right) + X_\sigma$$
where $RSSI_0 = -59$ dBm is the calibrated 1-meter reference RSSI, $n = 2.4$ is the indoor path loss exponent, and $X_\sigma \sim \mathcal{N}(0, \sigma^2)$ is zero-mean Gaussian shadowing noise.

The estimated distance is:
$$\hat{d} = d_0 \cdot 10^{\frac{RSSI_0 - RSSI}{10n}}$$
* **Proximity State Categorization:**
  $$\text{State}(d) = \begin{cases} \text{IMMEDIATE} & d \le 1.5\text{m} \\ \text{NEAR} & 1.5\text{m} < d \le 2.5\text{m} \\ \text{FAR} & 2.5\text{m} < d \le 4.0\text{m} \implies \text{Penalty: } +0.10 \\ \text{OUT\_OF\_RANGE} & d > 4.0\text{m} \implies \text{Penalty: } +0.25 \end{cases}$$

## 3.3 Deep SVDD Keystroke Biometric Sequence Modeling
To capture temporal typing rhythms without loss of sequential structure, we employ a 1D Convolutional Neural Network trained via Deep SVDD:
* **Objective Function:**
  Given authentic keystroke sequences $\mathbf{X} = \{\mathbf{x}_1, \dots, \mathbf{x}_N\}$ where each $\mathbf{x}_i \in \mathbb{R}^{2 \times 30}$ represents 30 sequential (dwell, flight) pairs, the network parameters $\mathcal{W}$ are optimized by:
  $$\min_{\mathcal{W}} \frac{1}{N} \sum_{i=1}^N \|\phi(\mathbf{x}_i; \mathcal{W}) - \mathbf{c}\|^2 + \frac{\lambda}{2} \sum_{l=1}^L \|\mathbf{W}_l\|_F^2$$
  where $\mathbf{c} \in \mathbb{R}^{16}$ is the pre-computed center of the hypersphere obtained by a forward pass through the initialized network:
  $$\mathbf{c} = \frac{1}{N} \sum_{i=1}^N \phi(\mathbf{x}_i; \mathcal{W}_0)$$
* **Sequence Confidence Output:**
  For a newly observed sequence $\mathbf{x}$, its distance from the hypersphere center is $s(\mathbf{x}) = \|\phi(\mathbf{x}; \mathcal{W}) - \mathbf{c}\|^2$, and confidence is computed as:
  $$C_{SVDD} = \exp\left(-\frac{s(\mathbf{x})}{\sigma^2}\right) \in [0.0, 1.0]$$

## 3.4 Multi-Factor Bayesian Threat Risk Fusion
The overall Bayesian Threat Confidence is formulated as a convex combination of four distinct security factors:
$$C_{fused} = w_{svdd} C_{SVDD} + w_{svm} C_{SVM} + w_{if} C_{IF} + w_{ctrl} C_{ctrl}$$
Calibrated weights:
$$w_{svdd} = 0.35, \quad w_{svm} = 0.35, \quad w_{if} = 0.15, \quad w_{ctrl} = 0.15$$
The raw threat risk index is:
$$R_{raw} = 1.0 - C_{fused}$$
Incorporating the environmental walk-away penalty $\Delta_{env} \in \{0.0, 0.10, 0.25\}$:
$$R_{instant} = \min\left(1.0, R_{raw} + \Delta_{env}\right)$$
To eliminate momentary statistical noise, the system maintains a rolling 30-second window queue ($\mathcal{H} = [R_1, R_2, R_3]$):
$$R_{smoothed} = \frac{1}{|\mathcal{H}|} \sum_{r \in \mathcal{H}} r$$

## 3.5 Formal Online Concept Drift Detection via ADWIN
To prevent false alarms caused by natural operator fatigue, we integrate the **Adaptive Windowing (ADWIN)** statistical change detector:
1. ADWIN maintains a variable-length window $W$ of recent observations.
2. For every possible partition of $W$ into two sub-windows $W_0$ and $W_1$ ($W = W_0 \cdot W_1$), it tests the hypothesis that the sub-window means $\mu_{W_0}$ and $\mu_{W_1}$ are equal.
3. **Hoeffding-Bound Rejection Cutoff:**
   $$\epsilon_{cut} = \sqrt{\frac{1}{2m} \cdot \ln\left(\frac{4}{\delta}\right)}$$
   where $m = \frac{1}{\frac{1}{|W_0|} + \frac{1}{|W_1|}}$ is the harmonic mean of window lengths and $\delta = 0.05$ represents the significance level.
4. **Drift Policy:**
   * If $|\hat{\mu}_{W_0} - \hat{\mu}_{W_1}| \ge \epsilon_{cut}$:
     - If the drift is gradual and user is authentic $\implies$ Retrain model boundaries (`adapt_to_verified_drift()`).
     - If the drift is abrupt and variance is high $\implies$ Trigger immediate threat escalation.

## 3.6 Graduated 3-Tier Dynamic Risk Orchestration Policy
| Risk Tier | Risk Threshold | Security Mechanism | User Impact |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Nominal)** | $R_{instant} < 0.40$ | Silent continuous background monitoring | **Zero friction; zero prompts** |
| **Tier 2 (Elevated)** | $0.40 \le R_{instant} \le 0.75$ | Non-blocking desktop toast challenge (`StepUpToastWidget`) | **Preserves keyboard focus and active work; verifies via OTP or master bypass** |
| **Tier 3 (Breach)** | $R_{instant} > 0.75$ | Fullscreen lockdown, silent webcam photo, and honeypot diversion | **Workstation locked; intruder diverted into honeypot** |
