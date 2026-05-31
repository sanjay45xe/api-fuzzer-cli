import asyncio
import time
import json
import httpx
from typing import Any, List, Tuple, Callable, Optional, Dict
from fuzzer.config import FuzzerConfig
from fuzzer.logger import FuzzResult

class FuzzEngine:
    def __init__(self, config: FuzzerConfig, on_request_complete: Optional[Callable[[FuzzResult], None]] = None):
        self.config = config
        self.on_request_complete = on_request_complete
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.results: List[FuzzResult] = []

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
                # To capture TTFB: we can read headers before reading body, or measure simple elapsed
                # time for the response headers to arrive (which is standard client.send or client.stream).
                # Using client.stream is the most accurate way to get Time To First Byte (TTFB).
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
