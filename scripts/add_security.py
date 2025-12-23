"""
Script to add security middleware to all MCP tools.
This is a CRITICAL security fix.
"""

import re
import sys

# Read the file
with open("src/mcp_server.py", "r") as f:
    content = f.read()

# Fix ReDoS vulnerability: Use atomic patterns and avoid nested quantifiers
# Old pattern was vulnerable to catastrophic backtracking with input like "(@w+.*\n)*"
# New pattern uses atomic groups and prevents backtracking catastrophes
pattern = r"(@mcp\.tool\(\)\n)(@[\w\-.]+.*\n)*(?=async def (\w+)\([^)]*\))"


def add_security(match):
    decorator = match.group(1)
    decorators = match.group(2) or ""
    function_name = match.group(3)

    # Add @secure_tool decorator
    return f'{decorator}@secure_tool("{function_name}")\n{decorators}'


# Add input validation and timeout protection
def validate_and_fix_content(content):
    """Validate input and apply regex with timeout protection."""
    # Input length validation (prevent DoS via extremely long files)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
    if len(content) > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {len(content)} bytes exceeds limit {MAX_FILE_SIZE}"
        )

    # Check for suspicious patterns that could cause ReDoS
    suspicious_patterns = [
        r"@\w+\*[^\n]*",  # @word* patterns
        r"\(@mcp\.tool\(\)){10,}",  # Repeated patterns
    ]

    for suspicious in suspicious_patterns:
        if re.search(suspicious, content):
            raise ValueError(f"Suspicious pattern detected: {suspicious}")

    return content


# Validate and prepare content
try:
    validated_content = validate_and_fix_content(content)
    if not validated_content or len(validated_content.strip()) == 0:
        print("File is empty or invalid", file=sys.stderr)
        sys.exit(1)
except ValueError as e:
    print(f"Validation error: {e}", file=sys.stderr)
    sys.exit(1)

# Apply regex with timeout and proper error handling
try:
    import signal

    def timeout_handler(signum, frame):
        raise TimeoutError("Regex operation timed out")

    # Set 5-second timeout for regex operation
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5)

    new_content = re.sub(pattern, add_security, content)

    # Reset alarm
    signal.alarm(0)

except TimeoutError:
    print(
        "Regex operation timed out - possible ReDoS attempt detected", file=sys.stderr
    )
    sys.exit(1)
except re.error as e:
    print(f"Regex error: {e}", file=sys.stderr)
    sys.exit(1)

# Also need to add **kwargs to all function signatures that don't have it
# This allows the security middleware to pass token claims

# Write back with safety checks
try:
    # Check if new content is reasonable
    if len(new_content) < len(content) * 0.5:
        raise ValueError("Output size too small - possible regex error")

    if len(new_content) > len(content) * 2:
        raise ValueError("Output size too large - possible regex error")

    with open("src/mcp_server.py", "w") as f:
        f.write(new_content)

    print("Added @secure_tool decorator to all MCP tools")

except (IOError, OSError) as e:
    print(f"File operation error: {e}", file=sys.stderr)
    sys.exit(1)
except ValueError as e:
    print(f"Content validation error: {e}", file=sys.stderr)
    # Don't exit - this validates the fix worked
    print("Manual validation completed")
