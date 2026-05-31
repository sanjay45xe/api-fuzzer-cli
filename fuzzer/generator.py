import json
import copy
from typing import Any, Dict, List, Tuple, Optional

# Constants for fuzzing
FUZZ_STRINGS = [
    "",
    "A" * 100,
    "A" * 1000,
    "A" * 10000,
    "\"'%;()&+--",  # SQL/XSS special characters injection indicators
    "\x00",         # Null byte
    "../../etc/passwd",  # Path traversal indicators
    "🚀🔥✨",       # Unicode / Emojis
]

FUZZ_NUMBERS = [
    0,
    -1,
    2147483647,      # Max 32-bit signed int
    -2147483648,     # Min 32-bit signed int
    9223372036854775807,  # Max 64-bit signed int
    -9223372036854775808, # Min 64-bit signed int
    1.7976931348623157e+308,  # Float overflow
    -1.7976931348623157e+308,
    3.14159,
    0.00000000000000001,
]

FUZZ_TYPES = [
    "string_type_swap",
    12345,
    True,
    False,
    None,
    [],
    {},
]

MALFORMED_JSON_TEMPLATES = [
    '{"key": "value"',            # Missing closing brace
    '{"key": "value",}',          # Trailing comma in dict
    '{"key": "value" "key2": 1}', # Missing comma separator
    '[1, 2, 3,',                  # Unclosed array with trailing comma
    '{"key": \x00\x01\x02}',       # Raw binary control characters
    '{"key": "value"}extra_junk', # Extra junk after JSON
    '{"a": ' * 100 + '1' + '}' * 50,  # Deeply nested unmatched braces
    '',                           # Empty payload
    'null',                       # Single null value (technically valid but often unhandled)
    '[]',                         # Empty array
    '{}',                         # Empty dict
]

def generate_payloads(template: Optional[Dict[str, Any]] = None) -> List[Tuple[Any, bool]]:
    """
    Generates list of fuzzed payloads based on a JSON template.
    Returns:
        List of tuples: (payload, is_malformed_json)
        If is_malformed_json is True, payload is a raw string that should be sent directly.
        Otherwise, payload is a dict/list to be serialized to JSON.
    """
    results: List[Tuple[Any, bool]] = []
    
    # 1. Add Malformed JSON Payloads
    for malformed in MALFORMED_JSON_TEMPLATES:
        results.append((malformed, True))
        
    # If no template is provided, we can only perform generic fuzzing
    if not template:
        # Fuzz standard body elements
        for val in FUZZ_STRINGS:
            results.append((val, False))
        for val in FUZZ_NUMBERS:
            results.append((val, False))
        for val in FUZZ_TYPES:
            results.append((val, False))
        return results

    # 2. Add baseline template (clean run)
    results.append((copy.deepcopy(template), False))

    # Helper function to detect type and return fuzz values
    def get_fuzz_values_for_value(val: Any) -> Tuple[List[Any], List[Any]]:
        # Returns (type_fuzz_list, boundary_fuzz_list)
        type_fuzz = []
        boundary_fuzz = []
        
        if isinstance(val, bool):
            # Boolean fuzzing
            type_fuzz = [s for s in FUZZ_TYPES if not isinstance(s, bool)]
            boundary_fuzz = ["true", "false", 1, 0, None]
        elif isinstance(val, (int, float)):
            # Number fuzzing
            type_fuzz = [s for s in FUZZ_TYPES if not isinstance(s, (int, float)) or isinstance(s, bool)]
            boundary_fuzz = FUZZ_NUMBERS
        elif isinstance(val, str):
            # String fuzzing
            type_fuzz = [s for s in FUZZ_TYPES if not isinstance(s, str)]
            boundary_fuzz = FUZZ_STRINGS
        elif isinstance(val, list):
            # List fuzzing
            type_fuzz = [s for s in FUZZ_TYPES if not isinstance(s, list)]
            boundary_fuzz = [[], [copy.deepcopy(val)], val * 10]
        elif isinstance(val, dict):
            # Dict fuzzing
            type_fuzz = [s for s in FUZZ_TYPES if not isinstance(s, dict)]
            boundary_fuzz = [{}, {k: v for k, v in val.items() if k != list(val.keys())[0]} if val else {}]
        else:
            type_fuzz = FUZZ_TYPES
            boundary_fuzz = []
            
        return type_fuzz, boundary_fuzz

    # 3. Fuzz each field in the template individually (preserving other fields)
    for key, val in template.items():
        type_fuzz_vals, boundary_fuzz_vals = get_fuzz_values_for_value(val)
        
        # Apply Type Fuzzing for this key
        for fuzz_val in type_fuzz_vals:
            new_payload = copy.deepcopy(template)
            new_payload[key] = fuzz_val
            results.append((new_payload, False))
            
        # Apply Boundary Fuzzing for this key
        for fuzz_val in boundary_fuzz_vals:
            new_payload = copy.deepcopy(template)
            new_payload[key] = fuzz_val
            results.append((new_payload, False))

    # 4. Fuzz all fields simultaneously
    all_fuzzed_payload = copy.deepcopy(template)
    for key, val in template.items():
        type_fuzz_vals, _ = get_fuzz_values_for_value(val)
        if type_fuzz_vals:
            # Pick a type swap
            all_fuzzed_payload[key] = type_fuzz_vals[0]
    results.append((all_fuzzed_payload, False))

    # Remove duplicates by converting to JSON strings and back to tuples
    seen = set()
    unique_results: List[Tuple[Any, bool]] = []
    for payload, is_malformed in results:
        if is_malformed:
            key_repr = (payload, True)
        else:
            # Use sorted dict keys to ensure identical dictionary serialization
            try:
                key_repr = (json.dumps(payload, sort_keys=True), False)
            except Exception:
                # If json serialization fails (e.g. invalid objects like NaN), use str representation
                key_repr = (str(payload), False)
        
        if key_repr not in seen:
            seen.add(key_repr)
            unique_results.append((payload, is_malformed))

    return unique_results
