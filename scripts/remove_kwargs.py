"""
Remove **kwargs from all tool function signatures.
FastMCP doesn't support **kwargs, so we use Context state instead.
"""

import re

with open("src/mcp_server.py", "r", encoding="utf-8") as f:
    content = f.read()

# Pattern to find signatures with , **kwargs
# Match: function_name(...params, **kwargs) -> ReturnType:
pattern = r"(async def \w+\([^)]*), \*\*kwargs(\) -> [^:]+:)"


def remove_kwargs(match):
    before = match.group(1)
    after = match.group(2)
    return f"{before}{after}"


# Replace all occurrences
new_content = re.sub(pattern, remove_kwargs, content)

# Also handle case where **kwargs is the only parameter
pattern2 = r"(async def \w+\()\*\*kwargs(\) -> [^:]+:)"
new_content = re.sub(pattern2, r"\1\2", new_content)

with open("src/mcp_server.py", "w", encoding="utf-8") as f:
    f.write(new_content)

print("✓ Removed **kwargs from all tool signatures")
