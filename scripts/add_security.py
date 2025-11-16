"""
Script to add security middleware to all MCP tools.
This is a CRITICAL security fix.
"""

import re

# Read the file
with open("src/mcp_server.py", "r") as f:
    content = f.read()

# Pattern to find @mcp.tool() followed by async def function_name(
pattern = r'(@mcp\.tool\(\))\n((?:@\w+.*\n)*)(async def (\w+)\([^)]*\))'

def add_security(match):
    decorator = match.group(1)
    other_decorators = match.group(2)
    function_def = match.group(3)
    function_name = match.group(4)
    
    # Add @secure_tool decorator
    return f'{decorator}\n@secure_tool("{function_name}")\n{other_decorators}{function_def}'

# Replace all occurrences
new_content = re.sub(pattern, add_security, content)

# Also need to add **kwargs to all function signatures that don't have it
# This allows the security middleware to pass token claims

# Write back
with open("src/mcp_server.py", "w") as f:
    f.write(new_content)

print("Added @secure_tool decorator to all MCP tools")
