import sys

sys.path.insert(0, "/home/mdlmarkham/Projects/TailOpsMCP")

from src.services.executor import (
    LocalExecutor,
    SSHExecutor,
    DockerExecutor,
    ExecutorConfig,
    ExecutorType,
    get_executor_factory,
)

print("Testing executor imports and instantiation...")
try:
    # Test LocalExecutor
    config = ExecutorConfig(
        executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
    )
    le = LocalExecutor(config)
    print(f"LocalExecutor: ✅ Created, has is_available: {hasattr(le, 'is_available')}")

except Exception as e:
    print(f"LocalExecutor: ❌ {e}")

try:
    # Test SSHExecutor
    config = ExecutorConfig(
        executor_type=ExecutorType.SSH,
        host="test.example.com",
        port=22,
        username="testuser",
        key_path="/path/to/key",
    )
    se = SSHExecutor(config)
    print(f"SSHExecutor: ✅ Created, has is_available: {hasattr(se, 'is_available')}")
except Exception as e:
    print(f"SSHExecutor: ❌ {e}")

try:
    # Test DockerExecutor
    config = ExecutorConfig(
        executor_type=ExecutorType.DOCKER,
        host=None,
        port=None,
        username=None,
        socket_path="/var/run/docker.sock",
    )
    de = DockerExecutor(config)
    print(
        f"DockerExecutor: ✅ Created, has is_available: {hasattr(de, 'is_available')}"
    )
except Exception as e:
    print(f"DockerExecutor: ❌ {e}")

# Test factory
try:
    factory = get_executor_factory()
    print(f"Factory: ✅ Registered executors: {list(factory._registry.keys())}")
except Exception as e:
    print(f"Factory: ❌ {e}")

print("\nAll imports successful!")
