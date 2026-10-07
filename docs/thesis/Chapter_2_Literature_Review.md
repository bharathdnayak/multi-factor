# CHAPTER 2: LITERATURE REVIEW

## 2.1 Evolution of User Authentication
Authentication systems have historically evolved across three classic paradigms:
1. **Something You Know:** Passwords, passphrases, and PINs. Susceptible to shoulder surfing, credential stuffing, phishing, and social engineering.
2. **Something You Have:** Hardware tokens (YubiKeys), smartcards, and SMS/TOTP authenticators. Vulnerable to SIM-swapping, session hijacking, and physical theft.
3. **Something You Are:** Physiological biometrics such as fingerprint, iris, and facial recognition. Highly reliable at static entry points, but irreversible if compromised and unusable for invisible continuous evaluation.

To overcome the vulnerabilities of static authentication, researchers introduced **Behavioral Biometrics**—measuring *how* a user interacts with input peripherals rather than *what* they physically possess or memorize.

## 2.2 Continuous Biometrics: Keystroke and Mouse Kinematics
### 2.2.1 Keystroke Dynamics
Keystroke dynamics analyzes the habitual neuro-muscular rhythms manifested during keyboard typing. Pioneered by Joyce and Gupta (1990) and extensively formalized by Killourhy and Maxion (IEEE DSN 2009), keystroke analysis focuses on two core temporal metrics:
* **Dwell Time ($T_{dwell}$):** The duration of time a physical key switch remains depressed from key-down to key-up:
  $$T_{dwell} = t_{key\_up} - t_{key\_down}$$
* **Flight Time ($T_{flight}$):** The latency between releasing a key and depressing the subsequent key:
  $$T_{flight} = t_{key\_down}^{(i+1)} - t_{key\_up}^{(i)}$$

Killourhy and Maxion established that benchmark statistical distance classifiers (Scaled Manhattan, Mahalanobis Distance, and One-Class SVM) achieve Equal Error Rates (EER) between 9.96% and 14.61% on fixed string typing. However, traditional models suffer significant performance degradation in free-text and continuous desktop environments due to arbitrary character sequences and typing speed variability.

### 2.2.2 Mouse Kinematics
Mouse dynamics study the continuous motor coordination of cursor movement. Early works by Gamboa and Fred (2004) and Ahmed and Traore (2007) established that human hand kinematics exhibit distinctive acceleration profiles, trajectory curvature, and velocity distributions. Zheng et al. (2011) demonstrated that mouse angle deviation and jerk (the derivative of acceleration):
$$\mathbf{j}(t) = \frac{d\mathbf{a}(t)}{dt} = \frac{d^3\mathbf{x}(t)}{dt^3}$$
serves as a discriminative biometric marker reflecting involuntary muscle tremor and biomechanical individuality.

## 2.3 Deep Learning and One-Class Anomaly Detection
In continuous endpoint security, obtaining labeled imposter training data is infeasible in practice; an authentic system owner can only train models on their own legitimate behavior. Consequently, authentication must be formulated as a **One-Class Classification (OCC)** or anomaly detection task.

Schölkopf et al. (2001) proposed the One-Class Support Vector Machine (OC-SVM), which projects data into a reproducing kernel Hilbert space (RKHS) and determines a max-margin hyperplane separating normal data from the coordinate origin. Liu et al. (2008) introduced Isolation Forests, which isolate anomalous points using binary random partition trees based on the premise that anomalies require fewer cuts to separate.

Recently, Ruff et al. (ICML 2018) introduced **Deep Support Vector Data Description (Deep SVDD)**, training deep neural networks to map input patterns into a minimal-volume hypersphere. When applied to 1D sequence biometrics, Deep SVDD eliminates manual feature engineering and captures temporal n-gram rhythms that shallow statistical models overlook.

## 2.4 Concept Drift and Adaptive Learning in Streaming Security
A primary limitation of existing continuous authentication systems is **Statistical Non-Stationarity** (Concept Drift). As a legitimate user works over extended periods, factors such as physical fatigue, psychological stress, changing cognitive tasks, or physical posture variations cause their behavioral feature distributions to drift over time.

Widmer and Kubat (1996) categorized concept drift into:
* **Gradual Drift:** Continuous, incremental changes in the underlying distribution over time.
* **Abrupt / Sudden Shift:** Instantaneous distribution changes caused by context changes or imposter takeover.

Bifet and Gavaldà (2007) introduced **Adaptive Windowing (ADWIN)**, a parameter-free online drift detection algorithm with rigorous mathematical guarantees based on Hoeffding's Inequality. Unlike fixed sliding windows, ADWIN dynamically adjusts its observation window size: expanding during stationary periods to improve estimation precision, and rapidly shrinking when statistically significant distribution differences between sub-windows emerge.

## 2.5 Cyber Deception, Honeypots, and Threat Attribution
When an authentication system detects an intrusion, conventional systems immediately terminate the session or lock the screen. While intuitive, this abrupt response alerts the adversary that they have been discovered, prompting them to disconnect, evade logs, or launch secondary attacks.

Spitzner (2002) formalized the concept of **Honeypots**—decoy resources designed to be probed, attacked, or compromised. In host-based deception, high-interaction honeypots emulate legitimate operating systems to observe adversarial techniques in real time. Al-Shaer et al. (2019) demonstrated that deceptive honey-tokens (fake database credentials, dummy cloud API keys, and quarantined file download traps) allow security teams to safely extract tactical threat intelligence without endangering production assets.

## 2.6 Critical Research Gaps in Contemporary Literature
A thorough examination of current academic and industry solutions reveals five critical gaps:
1. **Unimodal Isolation:** Most continuous authentication systems evaluate either keystroke dynamics or facial recognition in isolation, rendering them vulnerable to modality failure (e.g., poor lighting or idle keyboard).
2. **Ignorance of Concept Drift:** Prevailing systems employ static classification boundaries, leading to unacceptable false rejection rates (FRR) as genuine users tire.
3. **Disruptive Response Policies:** Existing systems enforce binary lockouts, frustrating legitimate users who experience brief behavioral variance.
4. **Passive Containment Without Deception:** Traditional systems fail to capture adversarial intelligence, immediately alerting intruders upon detection.
5. **Absence of Autonomous Forensic Attribution:** Existing solutions log raw event timestamps without mapping attacker actions to standardized cyber defense frameworks (e.g., MITRE ATT&CK) or producing audit-grade forensic documentation.
