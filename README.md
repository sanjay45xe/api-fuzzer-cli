API Fuzzer CLI
A high-performance, asynchronous CLI tool designed for API reliability testing and vulnerability discovery. This tool helps engineers identify input validation gaps, parser vulnerabilities, and unhandled server errors by stress-testing API endpoints with malformed and boundary-breaking payloads.

🛠 Features
Asynchronous Execution: Built with httpx and asyncio to handle high-concurrency request loads efficiently.

Intelligent Payload Generation:

Type Fuzzing: Swaps valid JSON types for anomalies (e.g., strings for booleans/lists).

Boundary/Overflow: Generates massive buffer overflows and extreme numerical values to test parser limits.

Malformed JSON: Injects structural anomalies like missing quotes and trailing separators.

Real-time Observability: A live terminal dashboard (using Rich) providing status code counts, latency distribution histograms, and progress tracking.

Structured Reporting: Automatically exports every event, payload, and response to fuzz_results.json for post-test analysis.

🚀 Quick Start
Prerequisites
Python 3.9+

A local environment with the necessary dependencies installed.

Setup
Bash
# Clone the repository
git clone https://github.com/sanjay45xe/api-fuzzer-cli
cd api-fuzzer-cli

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
Usage
Start your target server (or the included mock_server.py):

Bash
python -m uvicorn mock_server:app --port 8000
Run the Fuzzer:

Bash
python run_fuzzer.py http://127.0.0.1:8000/api/users --template user_template.json --concurrency 10 --output fuzz_results.json
📊 Dashboard Preview
┌─────────────────────────── API FUZZER DASHBOARD ────────────────────────────┐
│  ⚡ API FUZZER ENGINE v1.0.0 | Target: http://127.0.0.1:8000/api/users       │
│  Status Code Counts        TTFB Latency Histogram                           │
│  ┌────────────────────┬──────┐ ┌──────────────┬───────────────────┐         │
│  │ Success (2xx)      │   15 │ │ < 10ms       │ ░░░░░░░░░░░░░░░░… │         │
│  │ Client Errors (4xx)│   26 │ │ 100-250ms    │ ████████████████… │         │
│  │ Server Errors (5xx)│    7 │ │ > 1s         │ ███░░░░░░░░░░░░░… │         │
└─────────────────────────────────────────────────────────────────────────────┘
