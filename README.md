# Prompt Shelter 

 **Enterprise AI Security & Prompt Injection Detection Platform**  
 Protect LLM-backed applications against jailbreaks, system prompt extractions, role hijacking, and delimiter manipulation in real-time.

---

##  Overview

**Prompt Shelter** is a lightweight, zero-latency prompt evaluation engine built with Streamlit and Python. It analyzes incoming prompts against 20 precompiled, category-capped heuristic detection rules to classify inputs into **SAFE**, **SUSPICIOUS**, or **MALICIOUS** before they ever reach your LLM.

All evaluations are performed locally with zero external telemetry or LLM inference dependencies, making it compliant with strict data residency and air-gapped security policies.

---

##  Key Features

-  20 Specialized Detection Rules: Built-in regex and heuristic patterns covering:
  - Role manipulation (`ignore previous instructions`, `DAN mode`)
  - Authority impersonation (`developer mode`, `system override`)
  - Boundary & delimiter attacks (XML tags, triple markdown exploits)
  - Credential & prompt leakage (`reveal system prompt`, `leak API keys`)
-  Zero External API Dependencies: Instant local deterministic evaluation in sub-millisecond latency.
-  Real-Time Enterprise Dashboard:
  - Executive security posture metrics (Safe, Suspicious, Malicious count)
  - Daily evaluation volume trends
  - Triggered category distribution charts
-  Interactive Prompt Scanner:
  - Real-time scoring, matched signature breakdown, and severity weights.
  - Safe & malicious sample presets for one-click testing.
-  Scan Audit History & Export:
  - Persistent SQLite storage for audit tracking.
  - Full-text search and CSV export capabilities.
-  Sleek Enterprise UI:
  - Responsive collapsible sidebar with custom Lucide SVG line icons.
  - Strict light-theme typography and layout styling.
  - No dark-mode UI leaks or unstyled elements.

---

##  Project Architecture

```text
Prompt-Shelter/
├── app.py                     # Main Streamlit Dashboard & UI Layer
├── detection.py               # Rule-based Detection Engine (20 signatures + NFKC normalization)
├── storage.py                 # SQLite Persistence Layer for Scan History
├── requirements.txt           # Python dependencies
├── .streamlit/
│   └── config.toml            # Server & Theme configuration
├── docs/                      # Technical Documentation
│   ├── CHANGELOG.md           # Release & feature logs
│   ├── DETECTION_RULES.md     # Detailed specification of all 20 rules
│   ├── DETECTION_EVALUATION.md# Engine scoring rubric & false-positive controls
│   ├── PROJECT_ARCHITECTURE.md# System architecture & data flow
│   └── TESTING_GUIDE.md       # Unit and integration testing guide
└── tests/                     # 40 Test Suite Cases
    ├── test_detection.py
    ├── test_edge_cases.py
    ├── test_injection_prompts.py
    ├── test_normalization.py
    ├── test_safe_prompts.py
    └── test_scoring.py
```

---

##  Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/therafsanrohan/prompt-shelter.git
cd prompt-shelter
```

### 2. Set up virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit application
```bash
streamlit run app.py
```
Open [http://localhost:8501] in your browser.

---

##  Running Tests

The test suite covers normalization, individual rules, compound attacks, edge cases, and SQLite persistence (40 test cases total):

```bash
# Run all unit tests
python3 -m unittest discover -s tests -p "test_*.py"

# Run storage integration tests
python3 -m unittest test_detection_storage.py
```

---

##  Security & Privacy

Prompt Shelter operates strictly within your local environment or deployment container. It does not phone home, does not send prompts to external model providers, and complies with privacy requirements by sanitizing and hashing evaluated payloads.

---

##  License

Distributed under the MIT License. See `LICENSE` for details.
