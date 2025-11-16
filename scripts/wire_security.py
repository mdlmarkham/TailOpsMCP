"""Wire security middleware into all MCP tools - CRITICAL FIX"""
import re

with open('src/mcp_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
new_lines = []
i = 0

while i < len(lines):
    line = lines[i]
    
    # Found @mcp.tool()
    if line.strip() == '@mcp.tool()':
        # Check if already has @secure_tool on next line
        if i + 1 < len(lines) and '@secure_tool' in lines[i + 1]:
            new_lines.append(line)
            i += 1
            continue
        
        # Get next line to extract function name
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith('async def '):
            j += 1
        
        if j < len(lines):
            # Extract function name
            func_line = lines[j]
            match = re.search(r'async def (\w+)\(', func_line)
            if match:
                func_name = match.group(1)
                
                # Add @mcp.tool()
                new_lines.append(line)
                # Add @secure_tool
                new_lines.append(f'@secure_tool("{func_name}")')
                i += 1
                
                # Copy any decorators between @mcp.tool() and async def
                while i < j:
                    new_lines.append(lines[i])
                    i += 1
                
                # Fix function signature to add **kwargs if not present
                if '**kwargs' not in func_line:
                    # Find the closing paren before ->
                    if ') ->' in func_line:
                        func_line = func_line.replace(') ->', ', **kwargs) ->')
                    elif ')' in func_line:
                        # Single line signature
                        func_line = func_line.replace(')', ', **kwargs)')
                
                new_lines.append(func_line)
                i += 1
                continue
    
    new_lines.append(line)
    i += 1

with open('src/mcp_server.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines))

print('✓ Security middleware wired into all MCP tools')
