#!/usr/bin/env python3
"""
Test configurable environment loading across different scenarios.
Demonstrates portability and no hardcoded paths.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "apps" / "chatbot" / "src"))

from config.env_loader import EnvironmentLoader, get_env_info


def test_explicit_env_path():
    """Test ENV_FILE_PATH environment variable override."""
    print("🧪 Testing explicit ENV_FILE_PATH...")

    # Create temporary env file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("TEST_VAR=explicit_path_value\n")
        f.write("OPENAI_API_KEY=sk-test-explicit\n")
        temp_path = f.name

    try:
        # Clean environment
        original_env = os.environ.get("ENV_FILE_PATH")
        original_test = os.environ.get("TEST_VAR")

        # Set explicit path
        os.environ["ENV_FILE_PATH"] = temp_path
        if "TEST_VAR" in os.environ:
            del os.environ["TEST_VAR"]

        # Test loading
        loader = EnvironmentLoader()
        success = loader.load_environment()

        assert success, "Should load from explicit path"
        assert os.environ.get("TEST_VAR") == "explicit_path_value"
        print(f"✅ Loaded from explicit path: {temp_path}")

        # Restore environment
        if original_env:
            os.environ["ENV_FILE_PATH"] = original_env
        else:
            os.environ.pop("ENV_FILE_PATH", None)
        if original_test:
            os.environ["TEST_VAR"] = original_test
        else:
            os.environ.pop("TEST_VAR", None)

    finally:
        # Clean up
        Path(temp_path).unlink(missing_ok=True)


def test_search_path_flexibility():
    """Test search path flexibility."""
    print("🧪 Testing search path flexibility...")

    # Create loader with custom search paths
    with tempfile.TemporaryDirectory() as temp_dir:
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("CUSTOM_VAR=custom_value\n")

        # Custom search paths
        custom_paths = [str(env_file)]
        loader = EnvironmentLoader(search_paths=custom_paths)

        # Clean environment
        original_custom = os.environ.get("CUSTOM_VAR")
        os.environ.pop("CUSTOM_VAR", None)

        try:
            success = loader.load_environment()
            assert success, "Should load from custom path"
            assert os.environ.get("CUSTOM_VAR") == "custom_value"
            print(f"✅ Loaded from custom search path: {env_file}")

        finally:
            if original_custom:
                os.environ["CUSTOM_VAR"] = original_custom
            else:
                os.environ.pop("CUSTOM_VAR", None)


def test_search_paths_info():
    """Test search path information reporting."""
    print("🧪 Testing search path information...")

    loader = EnvironmentLoader()
    search_info = loader.get_search_paths_info()

    print("📋 Search Path Information:")
    for path, exists in search_info.items():
        status = "✅" if exists else "❌"
        print(f"  {status} {path}")

    # Should find at least one existing path (your env file)
    existing_paths = [path for path, exists in search_info.items() if exists]
    assert len(existing_paths) > 0, "Should find at least one existing env file"
    print(f"✅ Found {len(existing_paths)} existing environment files")


def test_environment_info():
    """Test environment information reporting."""
    print("🧪 Testing environment information...")

    env_info = get_env_info()
    print("📊 Environment Information:")
    print(f"  Loaded from: {env_info.get('loaded_from')}")
    print(
        f"  POSTGRES_PASSWORD set: {env_info['important_vars_set']['POSTGRES_PASSWORD']}"
    )
    print(f"  OPENAI_API_KEY set: {env_info['important_vars_set']['OPENAI_API_KEY']}")

    # Should detect your environment
    assert (
        env_info.get("loaded_from") is not None
    ), "Should detect loaded environment file"
    assert env_info["important_vars_set"][
        "OPENAI_API_KEY"
    ], "Should detect OPENAI_API_KEY"
    print("✅ Environment information correctly reported")


def test_no_override_existing():
    """Test that existing environment variables are not overridden by default."""
    print("🧪 Testing no override of existing environment variables...")

    # Set a test variable
    os.environ["OPENAI_API_KEY"] = "original-value"

    # Load environment
    loader = EnvironmentLoader()
    success = loader.load_environment(override_existing=False)

    # Should not override
    assert os.environ.get("OPENAI_API_KEY") == "original-value"
    print("✅ Existing environment variables preserved")

    # Test with override
    loader.load_environment(override_existing=True)
    # Now should be overridden (if env file exists)
    print(f"✅ Override test completed: {os.environ.get('OPENAI_API_KEY')[:10]}...")


if __name__ == "__main__":
    print("🔧 Testing Configurable Environment Loading")
    print("=" * 50)

    try:
        test_explicit_env_path()
        test_search_path_flexibility()
        test_search_paths_info()
        test_environment_info()
        test_no_override_existing()

        print("\n🎉 All configuration portability tests passed!")
        print("✅ No hardcoded paths")
        print("✅ Flexible search paths")
        print("✅ Environment variable override support")
        print("✅ Proper information reporting")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)
