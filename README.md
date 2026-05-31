# API Fuzzer CLI

A high-performance, asynchronous CLI tool designed for API reliability testing and vulnerability discovery. This tool helps engineers identify input validation gaps, parser vulnerabilities, and unhandled server errors by stress-testing API endpoints with malformed and boundary-breaking payloads.

# Features

- Asynchronous Execution**: Built with `httpx` and `asyncio` to handle high-concurrency request loads efficiently.
- Intelligent Payload Generation**:
  -Type Fuzzing**: Swaps valid JSON types for anomalies (e.g., strings for booleans/lists).
  -Boundary/Overflow**: Generates massive buffer overflows and extreme numerical values to test parser limits.
  -Malformed JSON**: Injects structural anomalies like missing quotes and trailing separators.
- Real-time Observability**: A live terminal dashboard (using `Rich`) providing status code counts, latency distribution histograms, and progress tracking.
- Structured Reporting**: Automatically exports every event, payload, and response to `fuzz_results.json` for post-test analysis.

# Quick Start

# Prerequisites:
- Python 3.9+

# Setup:

```bash
- Clone the repository
git clone [https://github.com/sanjay45xe/api-fuzzer-cli](https://github.com/sanjay45xe/api-fuzzer-cli)
cd api-fuzzer-cli

- Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

- Install dependencies
pip install -r requirements.txt
