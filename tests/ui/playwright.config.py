"""
Playwright configuration for different testing environments and modes.
Supports headless/headed testing, multiple browsers, and various scenarios.
"""

import os
from typing import Dict, Any, List


class PlaywrightConfig:
    """Configuration manager for Playwright testing environments."""
    
    # Base configuration
    BASE_CONFIG = {
        "base_url": "http://localhost:8000",
        "timeout": 30000,
        "expect_timeout": 10000,
        "navigation_timeout": 30000,
        "action_timeout": 10000,
    }
    
    # Browser configurations
    BROWSER_CONFIGS = {
        "chromium": {
            "name": "chromium",
            "headless": False,
            "args": [
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor"
            ],
            "viewport": {"width": 1280, "height": 720}
        },
        "firefox": {
            "name": "firefox", 
            "headless": False,
            "viewport": {"width": 1280, "height": 720}
        },
        "webkit": {
            "name": "webkit",
            "headless": False,
            "viewport": {"width": 1280, "height": 720}
        }
    }
    
    # Environment-specific configurations
    ENVIRONMENT_CONFIGS = {
        "local": {
            "base_url": "http://localhost:8000",
            "headless": False,
            "trace": True,
            "screenshot": "only-on-failure",
            "video": "retain-on-failure"
        },
        "ci": {
            "base_url": "http://localhost:8000", 
            "headless": True,
            "trace": False,
            "screenshot": "only-on-failure",
            "video": "off"
        },
        "staging": {
            "base_url": "https://staging-cwe-chatbot.example.com",
            "headless": True,
            "trace": True,
            "screenshot": "only-on-failure", 
            "video": "retain-on-failure"
        },
        "production": {
            "base_url": "https://cwe-chatbot.example.com",
            "headless": True,
            "trace": True,
            "screenshot": "only-on-failure",
            "video": "retain-on-failure"
        }
    }
    
    # Test execution configurations
    TEST_CONFIGS = {
        "smoke": {
            "tests": ["test_basic_navigation", "test_role_selection"],
            "parallel": 1,
            "timeout": 60000
        },
        "regression": {
            "tests": ["test_*"],
            "parallel": 2,
            "timeout": 120000
        },
        "security": {
            "tests": ["test_security_*", "test_input_sanitization"],
            "parallel": 1,
            "timeout": 180000
        },
        "performance": {
            "tests": ["test_performance_*"],
            "parallel": 1,
            "timeout": 300000
        }
    }
    
    @classmethod
    def get_config(cls, environment: str = None, browser: str = None, test_type: str = None) -> Dict[str, Any]:
        """Get complete configuration for specified parameters."""
        # Default environment from environment variable or 'local'
        env = environment or os.getenv("TEST_ENV", "local")
        
        # Default browser from environment variable or 'chromium'
        browser_name = browser or os.getenv("PLAYWRIGHT_BROWSER", "chromium")
        
        # Default test type
        test_suite = test_type or os.getenv("TEST_SUITE", "regression")
        
        # Build complete configuration
        config = cls.BASE_CONFIG.copy()
        
        # Add environment-specific settings
        if env in cls.ENVIRONMENT_CONFIGS:
            config.update(cls.ENVIRONMENT_CONFIGS[env])
        
        # Add browser-specific settings
        if browser_name in cls.BROWSER_CONFIGS:
            config["browser"] = cls.BROWSER_CONFIGS[browser_name]
        
        # Add test-specific settings
        if test_suite in cls.TEST_CONFIGS:
            config["test_config"] = cls.TEST_CONFIGS[test_suite]
        
        # Override with environment variables
        config.update(cls._get_env_overrides())
        
        return config
    
    @classmethod
    def _get_env_overrides(cls) -> Dict[str, Any]:
        """Get configuration overrides from environment variables."""
        overrides = {}
        
        # URL override
        if os.getenv("CHAINLIT_BASE_URL"):
            overrides["base_url"] = os.getenv("CHAINLIT_BASE_URL")
        
        # Headless mode override
        headless_env = os.getenv("PLAYWRIGHT_HEADLESS")
        if headless_env is not None:
            overrides["headless"] = headless_env.lower() in ("true", "1", "yes")
        
        # Screenshot mode override
        if os.getenv("PLAYWRIGHT_SCREENSHOT"):
            overrides["screenshot"] = os.getenv("PLAYWRIGHT_SCREENSHOT")
        
        # Video recording override
        if os.getenv("PLAYWRIGHT_VIDEO"):
            overrides["video"] = os.getenv("PLAYWRIGHT_VIDEO")
        
        # Trace recording override
        trace_env = os.getenv("PLAYWRIGHT_TRACE")
        if trace_env is not None:
            overrides["trace"] = trace_env.lower() in ("true", "1", "yes")
        
        # Timeout overrides
        if os.getenv("PLAYWRIGHT_TIMEOUT"):
            try:
                overrides["timeout"] = int(os.getenv("PLAYWRIGHT_TIMEOUT"))
            except ValueError:
                pass
        
        return overrides
    
    @classmethod
    def get_pytest_args(cls, environment: str = None, browser: str = None) -> List[str]:
        """Get pytest command line arguments for the configuration."""
        config = cls.get_config(environment, browser)
        
        args = []
        
        # Browser selection
        if "browser" in config:
            browser_name = config["browser"]["name"]
            args.extend(["--browser", browser_name])
        
        # Headless mode
        if config.get("headless", False):
            args.append("--headless")
        else:
            args.append("--headed")
        
        # Base URL
        if config.get("base_url"):
            args.extend(["--base-url", config["base_url"]])
        
        # Screenshot mode
        if config.get("screenshot"):
            args.extend(["--screenshot", config["screenshot"]])
        
        # Video recording
        if config.get("video") and config["video"] != "off":
            args.extend(["--video", config["video"]])
        
        # Tracing
        if config.get("trace", False):
            args.append("--tracing=on")
        
        # Timeout
        if config.get("timeout"):
            args.extend(["--timeout", str(config["timeout"])])
        
        return args
    
    @classmethod
    def create_env_file(cls, environment: str, output_path: str = ".env.test"):
        """Create environment file for test configuration."""
        config = cls.get_config(environment)
        
        env_vars = [
            f"TEST_ENV={environment}",
            f"CHAINLIT_BASE_URL={config.get('base_url', 'http://localhost:8000')}",
            f"PLAYWRIGHT_HEADLESS={str(config.get('headless', False)).lower()}",
            f"PLAYWRIGHT_SCREENSHOT={config.get('screenshot', 'only-on-failure')}",
            f"PLAYWRIGHT_VIDEO={config.get('video', 'retain-on-failure')}",
            f"PLAYWRIGHT_TRACE={str(config.get('trace', False)).lower()}",
            f"PLAYWRIGHT_TIMEOUT={config.get('timeout', 30000)}"
        ]
        
        with open(output_path, 'w') as f:
            f.write("# Playwright test environment configuration\n")
            f.write("# Generated automatically - do not edit manually\n\n")
            for var in env_vars:
                f.write(f"{var}\n")
        
        print(f"Environment configuration written to {output_path}")


# Predefined configurations for common scenarios
INTERACTIVE_CONFIG = PlaywrightConfig.get_config("local", "chromium")
CI_CONFIG = PlaywrightConfig.get_config("ci", "chromium")
CROSS_BROWSER_CONFIG = {
    "chromium": PlaywrightConfig.get_config("local", "chromium"),
    "firefox": PlaywrightConfig.get_config("local", "firefox"), 
    "webkit": PlaywrightConfig.get_config("local", "webkit")
}


# Utility functions
def get_interactive_config() -> Dict[str, Any]:
    """Get configuration optimized for interactive testing."""
    return INTERACTIVE_CONFIG


def get_ci_config() -> Dict[str, Any]:
    """Get configuration optimized for CI/CD environments."""
    return CI_CONFIG


def get_config_for_browser(browser: str) -> Dict[str, Any]:
    """Get configuration for a specific browser."""
    return PlaywrightConfig.get_config(browser=browser)


def print_current_config():
    """Print the current configuration for debugging."""
    config = PlaywrightConfig.get_config()
    print("Current Playwright Configuration:")
    print("=" * 40)
    for key, value in config.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    # CLI for generating configuration files
    import sys
    
    if len(sys.argv) > 1:
        env = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else ".env.test"
        PlaywrightConfig.create_env_file(env, output_file)
    else:
        print_current_config()