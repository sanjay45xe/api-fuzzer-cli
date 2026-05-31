import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

logger = logging.getLogger("api_fuzzer")
logger.setLevel(logging.INFO)

# Formatter and StreamHandler for basic command line logging
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

class FuzzResult(BaseModel):
    payload: Any
    is_malformed_json: bool = False
    status_code: Optional[int] = None
    ttfb: Optional[float] = None
    timeout: bool = False
    error: Optional[str] = None
    response_body: Optional[str] = None

class FuzzSessionLogger:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.results: List[Dict[str, Any]] = []

    def log_result(self, result: FuzzResult):
        self.results.append(result.model_dump())
        
        # Log to Python logging if there is an error
        if result.timeout:
            logger.warning(f"Connection timeout with payload: {result.payload}")
        elif result.error:
            logger.error(f"Request exception: {result.error} for payload: {result.payload}")
        elif result.status_code and result.status_code >= 500:
            logger.error(f"Server Error ({result.status_code}) for payload: {result.payload}")

    def save(self):
        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Structured results saved to {self.output_path}")
        except Exception as e:
            logger.critical(f"Failed to save fuzz results to {self.output_path}: {e}")
