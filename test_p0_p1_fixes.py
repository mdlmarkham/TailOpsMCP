"""
Quick test to verify P0 and P1 fixes are working correctly.
"""

import sys
sys.path.insert(0, '.')

def test_p0_cpu_fix():
    """Test that CPU call uses interval=None (non-blocking)."""
    print("Testing P0 fix: Non-blocking CPU measurement...")
    
    with open('src/mcp_server.py', 'r') as f:
        content = f.read()
    
    # Check that we're using interval=None, not interval=0.1 or interval=1
    if 'cpu_percent(interval=None)' in content:
        print("  ✓ Found: cpu_percent(interval=None) - non-blocking")
        if 'cpu_percent(interval=0.1)' not in content and 'cpu_percent(interval=1)' not in content:
            print("  ✓ PASS: No blocking CPU calls found")
            return True
        else:
            print("  ✗ FAIL: Found blocking CPU calls")
            return False
    else:
        print("  ✗ FAIL: cpu_percent(interval=None) not found")
        return False

def test_p1_docker_singleton():
    """Test that Docker client singleton exists."""
    print("\nTesting P1 fix: Docker client singleton...")
    
    try:
        from src.mcp_server import get_docker_client
        print("  ✓ get_docker_client function exists")
        
        # Check the source code has the singleton pattern
        with open('src/mcp_server.py', 'r') as f:
            content = f.read()
        
        if '_docker_client = None' in content and 'def get_docker_client()' in content:
            print("  ✓ Docker client singleton pattern found in code")
            
            # Check that tools use get_docker_client() instead of docker.from_env()
            docker_from_env_count = content.count('docker.from_env()')
            get_client_count = content.count('get_docker_client()')
            
            # Should have 1 docker.from_env() in the singleton, rest use get_docker_client()
            if docker_from_env_count == 1 and get_client_count >= 5:
                print(f"  ✓ Tools using singleton: {get_client_count} calls to get_docker_client()")
                print(f"  ✓ Only 1 docker.from_env() call (in singleton)")
                print("  ✓ PASS: Docker client singleton properly implemented")
                return True
            else:
                print(f"  ✗ docker.from_env() count: {docker_from_env_count} (expected 1)")
                print(f"  ✗ get_docker_client() count: {get_client_count} (expected >= 5)")
                return False
        else:
            print("  ✗ FAIL: Singleton pattern not found")
            return False
    except Exception as e:
        print(f"  ✗ FAIL: Error importing: {e}")
        return False

def test_p1_format_parameter():
    """Test that TOON format is available on key list functions."""
    print("\nTesting P1 fix: TOON format on all tools...")
    
    with open('src/mcp_server.py', 'r') as f:
        content = f.read()
    
    tools_to_check = [
        'get_container_list',
        'get_docker_networks',
        'list_docker_images',
        'get_top_processes',
        'get_network_status',
    ]
    
    all_passed = True
    for tool_name in tools_to_check:
        # Look for the function signature with format parameter
        search_pattern = f'async def {tool_name}('
        if search_pattern in content:
            # Find the function definition
            start_idx = content.find(search_pattern)
            # Get a chunk after the function def to check for format param
            chunk = content[start_idx:start_idx+300]
            
            if 'format: Literal["json", "toon"]' in chunk or "format: Literal['json', 'toon']" in chunk:
                print(f"  ✓ {tool_name} has format parameter")
            else:
                print(f"  ✗ {tool_name} missing format parameter")
                all_passed = False
        else:
            print(f"  ✗ {tool_name} function not found")
            all_passed = False
    
    if all_passed:
        print(f"  ✓ PASS: All checked tools support TOON format")
    else:
        print(f"  ✗ FAIL: Some tools missing format parameter")
    
    return all_passed

def main():
    print("=" * 60)
    print("P0/P1 Fixes Verification Test")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(test_p0_cpu_fix())
    except Exception as e:
        print(f"  ✗ P0 test failed with error: {e}")
        results.append(False)
    
    try:
        results.append(test_p1_docker_singleton())
    except Exception as e:
        print(f"  ✗ P1 Docker singleton test failed: {e}")
        results.append(False)
    
    try:
        results.append(test_p1_format_parameter())
    except Exception as e:
        print(f"  ✗ P1 format parameter test failed: {e}")
        results.append(False)
    
    print("\n" + "=" * 60)
    if all(results):
        print("✓ ALL TESTS PASSED!")
        print("=" * 60)
        return 0
    else:
        print(f"✗ SOME TESTS FAILED ({sum(results)}/{len(results)} passed)")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
