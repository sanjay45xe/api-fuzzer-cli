import asyncio
import time
import json
import csv
import os
import datetime
import httpx
from typing import Any, List, Tuple, Callable, Optional, Dict
from fuzzer.config import FuzzerConfig
from fuzzer.logger import FuzzResult

class FuzzEngine:
    def __init__(self, config: FuzzerConfig, on_request_complete: Optional[Callable[[FuzzResult], None]] = None, csv_path: str = "fuzz_results.csv"):
        self.config = config
        self.on_request_complete = on_request_complete
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.results: List[FuzzResult] = []
        self.csv_path = csv_path
        self.csv_lock = asyncio.Lock()
        
        # Initialize the CSV file with headers
        self._init_csv()

    def _init_csv(self):
        try:
            with open(self.csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "status_code", "ttfb_ms", "timeout", "error", "payload"])
        except Exception as e:
            print(f"Error initializing CSV log file {self.csv_path}: {e}")

    async def _log_to_csv(self, result: FuzzResult):
        async with self.csv_lock:
            try:
                # Append single completed request details to CSV
                with open(self.csv_path, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.datetime.now().isoformat(),
                        result.status_code if result.status_code is not None else "",
                        f"{result.ttfb * 1000:.2f}" if result.ttfb is not None else "",
                        result.timeout,
                        result.error if result.error is not None else "",
                        json.dumps(result.payload) if not result.is_malformed_json else result.payload
                    ])
            except Exception as e:
                print(f"Error writing request metrics to CSV: {e}")

    async def _send_request(self, client: httpx.AsyncClient, payload: Any, is_malformed_json: bool) -> FuzzResult:
        headers = self.config.headers.copy()
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        # Prepare request content
        content: Optional[bytes] = None
        data_json: Optional[Any] = None

        if self.config.method in ["POST", "PUT", "PATCH"]:
            if is_malformed_json:
                # Raw string for malformed JSON injection
                content = str(payload).encode("utf-8", errors="ignore")
            else:
                try:
                    # Use standard serialization, handle NaN/Infinity
                    content = json.dumps(payload, allow_nan=True).encode("utf-8")
                except Exception as e:
                    # Fallback to direct serialization
                    content = str(payload).encode("utf-8")
        else:
            # For GET or other requests, if there's a payload, append as query parameters
            if not is_malformed_json and isinstance(payload, dict):
                data_json = payload

        start_time = time.perf_counter()
        status_code = None
        ttfb = None
        timeout = False
        error_msg = None
        response_body = None

        async with self.semaphore:
            try:
                # Custom request handling
                # To capture TTFB: stream using client.stream to measure Time To First Byte (TTFB) accurately
                async with client.stream(
                    method=self.config.method,
                    url=self.config.url,
                    headers=headers,
                    content=content,
                    params=data_json if self.config.method == "GET" else None,
                    timeout=self.config.timeout
                ) as response:
                    ttfb = time.perf_counter() - start_time
                    status_code = response.status_code
                    # Read the response body in case there's an error message
                    body_parts = []
                    async for chunk in response.aiter_bytes():
                        body_parts.append(chunk)
                    response_body = b"".join(body_parts).decode("utf-8", errors="ignore")
                    
            except httpx.ConnectTimeout as e:
                timeout = True
                error_msg = f"Connection Timeout: {str(e)}"
            except httpx.ReadTimeout as e:
                timeout = True
                error_msg = f"Read Timeout: {str(e)}"
            except httpx.HTTPError as e:
                error_msg = f"HTTP Error: {str(e)}"
            except Exception as e:
                error_msg = f"Unexpected Exception: {str(e)}"

        # If ttfb was not set (e.g. error occurred before headers), calculate it
        if ttfb is None:
            ttfb = time.perf_counter() - start_time

        result = FuzzResult(
            payload=payload,
            is_malformed_json=is_malformed_json,
            status_code=status_code,
            ttfb=ttfb,
            timeout=timeout,
            error=error_msg,
            response_body=response_body[:1000] if response_body else None # Cap body logging size
        )

        self.results.append(result)

        # Log result locally to CSV
        await self._log_to_csv(result)

        if self.on_request_complete:
            # Invoke callback (handles real-time UI/logging updates)
            if asyncio.iscoroutinefunction(self.on_request_complete):
                await self.on_request_complete(result)
            else:
                self.on_request_complete(result)

        return result

    async def run(self, payloads: List[Tuple[Any, bool]]) -> List[FuzzResult]:
        limits = httpx.Limits(max_keepalive_connections=self.config.concurrency, max_connections=self.config.concurrency * 2)
        async with httpx.AsyncClient(limits=limits, verify=False) as client:
            tasks = [
                self._send_request(client, payload, is_malformed)
                for payload, is_malformed in payloads
            ]
            await asyncio.gather(*tasks)
        return self.results
