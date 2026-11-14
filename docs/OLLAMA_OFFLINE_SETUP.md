# Offline Ollama AI Threat Reasoner: Setup & Operational Guide

**Project:** Behavioral Drift Continuous Security  
**Module:** `deception/ai_intent_analyzer.py` — Local Offline AI DFIR Threat Analysis  
**Operating Environment:** Windows 10 / Windows 11 (64-bit)  
**Status:** **Fully Automated, Robust & Production-Hardened**

---

## 1. Overview & Architecture

The Honeypot Deception Subsystem integrates an **on-device, offline Large Language Model (LLM)** to perform automated Cyber Forensics & Incident Response (DFIR) analysis of intruder sessions inside the honeypot desktop.

### Key Operational Guarantees:
1. **100% Offline & Private:** Zero telemetry or evidence leaves the local machine. All inference runs directly on host CPU or GPU via Ollama.
2. **Automatic Service Lifecycle:** If the Ollama background daemon is offline, `AIIntentAnalyzer` automatically locates the executable on disk, spawns `ollama serve`, and waits for HTTP readiness.
3. **Deterministic Fallback Engine:** If Ollama is not installed, the model is missing, or the model produces non-compliant output, the system deterministically falls back to authoritative rule-based threat heuristics with zero application crashes.
4. **Truthful Minimal-Session Analysis:** For 1-event probe sessions (e.g., initial biometric lockout without intruder activity), the analyzer reports an inconclusive perimeter probe, avoiding hallucinated claims of credential theft or directory enumeration.

---

## 2. Ollama Installation & Executable Discovery

### 2.1 Standard Windows Installation
1. Download Ollama for Windows from [https://ollama.com/download](https://ollama.com/download).
2. Run the installer (`OllamaSetup.exe`). The standard installation path is:
   ```
   C:\Users\<User>\AppData\Local\Programs\Ollama\ollama.exe
   ```
3. The system automatically inspects the following paths in priority order:
   - `OLLAMA_PATH` environment variable (if explicitly set).
   - `%LOCALAPPDATA%\Programs\Ollama\ollama.exe`.
   - `%PROGRAMFILES%\Ollama\ollama.exe`.
   - System `%PATH%` via `where.exe ollama`.

---

## 3. Recommended Compact Models for Laptop Presentation

For live academic examinations and laptop demonstrations, low inference latency is paramount. The system prioritizes lightweight, high-speed models:

| Model | Size | RAM Required | Typical Inference Time | Recommended Use |
| :--- | :---: | :---: | :---: | :--- |
| **`qwen2.5:1.5b`** | **0.9 GB** | **~2 GB** | **2 – 6 seconds** | **Primary Recommendation:** Instantaneous viva reporting on CPU or GPU. |
| **`deepseek-r1:1.5b`** | **1.1 GB** | **~2 GB** | **3 – 8 seconds** | Fast chain-of-thought forensic reasoning. |
| **`qwen2.5:3b`** | **2.0 GB** | **~4 GB** | **6 – 12 seconds** | Balanced narrative depth on mid-tier hardware. |
| **`qwen2.5:7b`** | **4.7 GB** | **~8 GB** | **15 – 35 seconds** | High-depth DFIR reporting on systems with dedicated GPUs. |

### Pulling the Recommended Model:
Open Command Prompt and run:
```cmd
ollama pull qwen2.5:1.5b
```

---

## 4. Execution Timeout & Robust JSON Extraction

### 4.1 Configurable Timeout
The default HTTP query timeout is set to **35 seconds** (upgraded from 15 seconds), accommodating cold-boot model loading on laptop CPUs.
To override for slower hardware, set the environment variable in `.env`:
```env
OLLAMA_TIMEOUT=60
```

### 4.2 Multi-Stage RFC-Compliant JSON Parser
LLMs frequently prepend conversational greetings or enclose responses in markdown code blocks (` ```json ... ``` `) or reasoning tags (`<think> ... </think>`). The hardened parser executes a multi-stage cleanup pipeline:
1. Strips `<think>...</think>` internal monologue blocks.
2. Extracts inner content from fenced markdown blocks.
3. Cleans unescaped control characters and newlines within JSON string values.
4. Performs bracket-balanced boundary slicing to isolate the root JSON object `{ ... }`.
5. Validates all mandatory DFIR keys (`threat_level`, `motive_assessment`, `executive_assessment`, `observed_facts`, `recommended_actions`). If JSON validation fails, the system seamlessly transitions to the deterministic heuristic engine without raising errors.

---

## 5. Testing & Verification

You can verify the Ollama integration and fallback mechanics using the test suite:
```cmd
python -m unittest tests.test_hardened_forensic_pipeline.TestAIIntentAnalyzerHardening
```
Or run pre-flight diagnostics:
```cmd
bat\doctor.bat --no-pause
```
