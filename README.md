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

Prerequisites: Python 3.9+

Setup:

```bash
# Clone the repository
git clone [https://github.com/sanjay45xe/api-fuzzer-cli](https://github.com/sanjay45xe/api-fuzzer-cli)
cd api-fuzzer-cli

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```
# Usage

Start your target server:
```bash
python -m uvicorn mock_server:app --port 8000
```
Run the Fuzzer:
```bash
python run_fuzzer.py [http://127.0.0.1:8000/api/users](http://127.0.0.1:8000/api/users) --template user_template.json --concurrency 10 --output fuzz_results.json
```
<img width="1919" height="1021" alt="Screenshot 2026-05-31 155331" src="https://github.com/user-attachments/assets/08da170a-f416-4100-a665-78bf0b92b9bb" />
<img width="1915" height="814" alt="Screenshot 2026-05-31 155429" src="https://github.com/user-attachments/assets/884862f0-305e-4057-969d-b11fcbab172d" />
<img width="1899" height="363" alt="Screenshot 2026-05-31 155448" src="https://github.com/user-attachments/assets/2dd528cf-9ffc-49c9-81b4-58d0ad04f431" />



