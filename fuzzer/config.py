from typing import Dict, Optional
from pydantic import BaseModel, Field, field_validator
import urllib.parse

class FuzzerConfig(BaseModel):
    url: str = Field(..., description="The target API endpoint URL.")
    method: str = Field("POST", description="HTTP method to use (e.g., GET, POST, PUT, DELETE, PATCH).")
    template_path: Optional[str] = Field(None, description="Path to the JSON template file for fuzzing structure.")
    concurrency: int = Field(10, ge=1, le=500, description="Number of concurrent requests (semaphore limit).")
    timeout: float = Field(5.0, gt=0, description="HTTP connection and read timeout in seconds.")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers to include in requests.")
    output: str = Field("fuzz_results.json", description="File path to save the structured fuzzing results.")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urllib.parse.urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("URL must have a valid scheme (e.g. http or https) and a network location.")
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        upper_val = v.upper()
        allowed = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
        if upper_val not in allowed:
            raise ValueError(f"HTTP method must be one of {allowed}")
        return upper_val
