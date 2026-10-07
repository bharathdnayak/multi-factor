# CHAPTER 1: INTRODUCTION

## 1.1 Overview and Background
In modern distributed computing and corporate enterprise environments, endpoint workstation security constitutes the primary frontline against cyber threats. Traditional access management systems have almost universally relied upon point-of-entry authentication mechanisms. These perimeter-based protocols—encompassing static passwords, cryptographic PINs, physical smartcards, and biometric fingerprint or facial scans—validate a user's identity exclusively at the initial session boundary.

Once this initial cryptographic handshake succeeds, the operating system enters an implicitly trusted execution state. The workstation remains completely unlocked and accessible until an explicit manual logout occurs or an arbitrary operating system idle timer (typically 10 to 15 minutes) triggers a screen lockout. During this vulnerability window, the computer system operates under the naive and perilous assumption that the person manipulating the physical peripherals remains the authentic, authorized individual who initially logged in.

## 1.2 Motivation and Industry Relevance
The vulnerability inherent in static perimeter authentication gives rise to the critical security risk known as the **Physical Takeover Attack** or the "Coffee Break Intrusion":
1. **The Walk-Away Window:** An authorized employee temporarily leaves their workstation unattended to consult a colleague, take a phone call, or visit the cafeteria.
2. **Immediate Insider Exploitation:** An unauthorized insider, visitor, or malicious actor physically sits down at the unlocked machine. Within 30 seconds, an intruder can exfiltrate intellectual property, extract browser-cached corporate passwords, plant persistent command-and-control (C2) payloads, or execute malicious administrative commands with the legitimate user's full privileges.
3. **Forensic Ambiguity:** Because the actions occur within the authentic user's authenticated session, system event logs erroneously attribute all adversarial actions to the legitimate employee, severely hindering post-incident forensic attribution.

Existing countermeasures, such as aggressive 60-second screen lockout timers or continuous facial recognition using webcams, introduce intolerable operational friction. Short idle timeouts disrupt user productivity during contemplation or reading tasks, while continuous facial recognition suffers from ambient lighting variations, head pose occlusions, and severe employee privacy concerns.

Consequently, there is an urgent industry and academic demand for a **Continuous, Zero-Friction Authentication and Active Defense Architecture** that invisibly and passively verifies identity through natural behavioral dynamics while seamlessly neutralizing intruders.

## 1.3 Problem Statement
To design, implement, and empirically validate an autonomous continuous endpoint security system that:
1. Passively captures multi-modal behavioral dynamics (keystroke timing sequences, mouse kinematics, intra-application cognitive context, and passive BLE proximity) without imposing workflow friction or capturing sensitive user plaintext.
2. Formulates an online concept drift detection mechanism capable of statistically distinguishing between natural user behavioral changes (e.g., typing fatigue) and acute unauthorized intruder substitutions.
3. Implements a graduated, multi-tier risk response policy that minimizes false challenge disruptions while enforcing immediate lockdown upon high-confidence intrusions.
4. Seamlessly diverts detected adversaries into an emulated, high-interaction deception honeypot sandbox to safely quarantine threat payloads and record tamper-evident forensic intelligence.
5. Employs offline, privacy-preserving artificial intelligence to automatically categorize adversary intent under the MITRE ATT&CK framework and compile audit-grade executive forensic reports.

## 1.4 Objectives of the Work
The primary engineering and research objectives of this project are:
* **Objective 1 (Multi-Modal Telemetry Acquisition):** Develop a low-overhead continuous sensing hook capturing millisecond-precision keystroke dwell and flight times, cursor kinematics (velocity, acceleration, jerk, curvature), intra-application focus, and environmental BLE proximity RSSI.
* **Objective 2 (Deep SVDD & Machine Learning Engine):** Engineer a hybrid machine learning pipeline combining a PyTorch 1D-CNN Deep Support Vector Data Description (Deep SVDD) sequence network with One-Class Support Vector Machines (OC-SVM) and Isolation Forests.
* **Objective 3 (Online Concept Drift Detection):** Implement the formal Adaptive Windowing (ADWIN) algorithm with Hoeffding-bound hypothesis testing to monitor streaming behavioral distributions and trigger online adaptation during legitimate user fatigue.
* **Objective 4 (Graduated 3-Tier Risk Orchestration):** Establish a dynamic 3-tier risk response policy comprising silent monitoring (Tier 1), a non-blocking desktop toast challenge (Tier 2), and autonomous lockdown with silent webcam capture (Tier 3).
* **Objective 5 (1:1 Deception Honeypot Environment):** Construct a high-interaction, pixel-perfect PyQt6 deception sandbox equipped with honey-token credentials, decoy web portals, emulated HoneyShell network reconnaissance traps, and safe remote C2 payload quarantine.
* **Objective 6 (Offline AI Threat Forensics & Reporting):** Integrate a local offline Ollama large language model to map captured attacker trajectories to MITRE ATT&CK tactics and generate publication-quality multi-page executive PDF incident reports.
* **Objective 7 (Scientific Benchmark Validation):** Evaluate the system against the public Carnegie Mellon University (CMU) Keystroke Dynamics Benchmark (51 subjects, 20,400 trials) using the Killourhy & Maxion protocol, as well as a real-world multi-user harvested cohort.

## 1.5 Scope and Operational Boundaries
* **Target Operating Environment:** Microsoft Windows 10 / 11 desktop and workstation environments, leveraging native Win32 APIs, Python 3.14, and PyQt6.
* **Modality Boundaries:** Keystroke dynamics, cursor kinematics, application context, and Bluetooth Low Energy (BLE) peripheral proximity. Invasive modalities (keylogging of plain alphanumeric content, continuous video surveillance) are strictly prohibited to maintain user privacy.
* **Computational Constraints:** Continuous daemon evaluation latency must remain under 50 milliseconds per 10-second window, maintaining a CPU duty cycle below 1.0% and memory consumption under 100 MB.

## 1.6 Organization of the Thesis Report
* **Chapter 1: Introduction** defines the research problem, motivation, operational scope, and specific technical objectives.
* **Chapter 2: Literature Review** examines state-of-the-art continuous biometric authentication, concept drift handling in streaming security, and cyber deception architectures, highlighting existing research gaps.
* **Chapter 3: System Design and Methodology** details the mathematical formulations, architectural diagrams, Bayesian threat fusion, ADWIN Hoeffding bounds, and deception mechanics.
* **Chapter 4: Implementation Details** elaborates on the multi-process supervisor, low-level OS hooks, feature extraction engine, HoneyShell emulation, and real-time FastAPI WebSocket dashboard.
* **Chapter 5: Experimental Results and Discussion** presents empirical evaluations on the 51-subject CMU dataset, field harvested user cohorts, latency profiling, and security robustness analysis.
* **Chapter 6: Conclusion and Future Scope** summarizes key research contributions, discusses practical limitations, and outlines future engineering enhancements.
