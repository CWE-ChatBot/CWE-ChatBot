#!/usr/bin/env python3
"""
Test runner script for Playwright UI tests.
Provides convenient commands for running different test scenarios.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

# Add current directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent))


def run_command(command: list, description: str = "") -> int:
    """Run a command and return the exit code."""
    if description:
        print(f"\n=== {description} ===")
    
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(command, cwd=Path(__file__).parent.parent.parent)
    return result.returncode


def install_system_dependencies():
    """Install system dependencies for Playwright browsers."""
    print("Installing Playwright system dependencies...")
    return run_command([
        "sudo", "playwright", "install-deps"
    ], "Installing system dependencies")


def run_basic_tests(headless: bool = False, browser: str = "chromium"):
    """Run basic navigation and smoke tests."""
    cmd = [
        "poetry", "run", "pytest", 
        "tests/ui/test_basic_navigation.py",
        "-v",
        f"--browser={browser}"
    ]
    
    if headless:
        cmd.append("--headless")
    else:
        cmd.append("--headed")
    
    return run_command(cmd, f"Running basic tests in {browser}")


def run_all_ui_tests(headless: bool = False, browser: str = "chromium"):
    """Run all UI tests."""
    cmd = [
        "poetry", "run", "pytest",
        "tests/ui/",
        "-v", 
        f"--browser={browser}",
        "--tb=short"
    ]
    
    if headless:
        cmd.append("--headless")
    else:
        cmd.append("--headed")
    
    return run_command(cmd, f"Running all UI tests in {browser}")


def run_cross_browser_tests(headless: bool = True):
    """Run tests across multiple browsers."""
    browsers = ["chromium", "firefox", "webkit"]
    results = {}
    
    for browser in browsers:
        print(f"\n{'='*50}")
        print(f"Testing with {browser.upper()}")
        print(f"{'='*50}")
        
        result = run_basic_tests(headless=headless, browser=browser)
        results[browser] = result
    
    # Summary
    print(f"\n{'='*50}")
    print("Cross-browser test summary:")
    print(f"{'='*50}")
    
    for browser, result in results.items():
        status = "PASSED" if result == 0 else "FAILED"
        print(f"{browser:10}: {status}")
    
    return all(result == 0 for result in results.values())


def run_interactive_test():
    """Run tests in interactive mode for debugging."""
    print("Starting interactive test mode...")
    print("Browser will open and stay open for manual testing")
    
    cmd = [
        "poetry", "run", "pytest",
        "tests/ui/test_basic_navigation.py::TestBasicNavigation::test_chainlit_interface_elements_present",
        "-v", "-s",
        "--headed",
        "--browser=chromium"
    ]
    
    return run_command(cmd, "Running interactive test")


def create_test_environment_file(env: str = "local"):
    """Create test environment configuration file."""
    try:
        # Import the local config module 
        import playwright.config as config_module
        output_file = f".env.test.{env}"
        config_module.PlaywrightConfig.create_env_file(env, output_file)
        print(f"Test environment file created: {output_file}")
        return 0
    except ImportError as e:
        print(f"Could not import playwright config: {e}")
        print("Creating basic environment file...")
        
        # Create a basic env file manually
        output_file = f".env.test.{env}"
        env_content = f"""# Playwright test environment configuration for {env}
TEST_ENV={env}
CHAINLIT_BASE_URL=http://localhost:8000
PLAYWRIGHT_HEADLESS={'true' if env == 'ci' else 'false'}
PLAYWRIGHT_SCREENSHOT=only-on-failure
PLAYWRIGHT_VIDEO=retain-on-failure
PLAYWRIGHT_TRACE={'false' if env == 'ci' else 'true'}
PLAYWRIGHT_TIMEOUT=30000
"""
        with open(output_file, 'w') as f:
            f.write(env_content)
        print(f"Basic environment file created: {output_file}")
        return 0


def check_prerequisites():
    """Check that prerequisites are installed."""
    print("Checking prerequisites...")
    
    # Check Poetry
    try:
        result = subprocess.run(["poetry", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Poetry: {result.stdout.strip()}")
        else:
            print("✗ Poetry not found")
            return False
    except FileNotFoundError:
        print("✗ Poetry not found")
        return False
    
    # Check Playwright installation  
    try:
        result = subprocess.run(["poetry", "run", "playwright", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Playwright: {result.stdout.strip()}")
        else:
            print("✗ Playwright not found in Poetry environment")
            return False
    except FileNotFoundError:
        print("✗ Playwright not found")
        return False
    
    # Check browsers
    try:
        result = subprocess.run(["poetry", "run", "playwright", "install", "--dry-run"], capture_output=True, text=True)
        if "chromium" in result.stdout or "browsers are already installed" in result.stdout:
            print("✓ Playwright browsers available")
        else:
            print("⚠ Playwright browsers may need installation")
    except:
        print("⚠ Could not check browser installation")
    
    return True


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description="Playwright UI test runner")
    parser.add_argument("command", choices=[
        "check", "install-deps", "basic", "all", "cross-browser", 
        "interactive", "config", "help"
    ], help="Command to run")
    
    parser.add_argument("--headless", action="store_true", 
                       help="Run tests in headless mode")
    parser.add_argument("--browser", default="chromium", 
                       choices=["chromium", "firefox", "webkit"],
                       help="Browser to use for testing")
    parser.add_argument("--env", default="local", 
                       choices=["local", "ci", "staging", "production"],
                       help="Environment configuration to use")
    
    args = parser.parse_args()
    
    if args.command == "help":
        print_help()
        return 0
    elif args.command == "check":
        return 0 if check_prerequisites() else 1
    elif args.command == "install-deps":
        return install_system_dependencies()
    elif args.command == "basic":
        return run_basic_tests(args.headless, args.browser)
    elif args.command == "all":
        return run_all_ui_tests(args.headless, args.browser)
    elif args.command == "cross-browser":
        return 0 if run_cross_browser_tests(args.headless) else 1
    elif args.command == "interactive":
        return run_interactive_test()
    elif args.command == "config":
        return create_test_environment_file(args.env)
    else:
        print(f"Unknown command: {args.command}")
        return 1


def print_help():
    """Print detailed help information."""
    help_text = """
Playwright UI Test Runner - CWE ChatBot Project

Commands:
  check           Check prerequisites (Poetry, Playwright, browsers)
  install-deps    Install system dependencies for Playwright browsers
  basic           Run basic navigation and smoke tests
  all             Run all UI tests
  cross-browser   Run tests across chromium, firefox, and webkit
  interactive     Run test in interactive mode for debugging
  config          Create test environment configuration file
  help            Show this help message

Options:
  --headless      Run tests in headless mode (no browser window)
  --browser       Specify browser: chromium, firefox, webkit (default: chromium)
  --env           Environment config: local, ci, staging, production (default: local)

Examples:
  python tests/ui/run_tests.py check                    # Check prerequisites
  python tests/ui/run_tests.py basic                    # Run basic tests with browser window
  python tests/ui/run_tests.py basic --headless         # Run basic tests headless
  python tests/ui/run_tests.py all --browser firefox    # Run all tests in Firefox
  python tests/ui/run_tests.py cross-browser --headless # Test all browsers headless
  python tests/ui/run_tests.py interactive              # Interactive debugging mode
  python tests/ui/run_tests.py config --env ci          # Create CI environment config

Prerequisites:
1. Poetry installed and project dependencies installed
2. Playwright browsers installed (poetry run playwright install)
3. Chainlit application running on localhost:8000 (for most tests)

Notes:
- Tests will create screenshots in test-results/screenshots/
- Use interactive mode for debugging test scenarios
- Cross-browser testing is recommended before releases
"""
    print(help_text)


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)