# UI Testing with Playwright - Story 2.6

This directory contains the Playwright-based UI testing framework for the CWE ChatBot application, implementing Story 2.6: Interactive UI/UX Testing Environment.

## Overview

The UI testing framework provides comprehensive browser automation testing for:
- **Role-based UI functionality testing** - All 5 user roles with context preservation and switching
- **Progressive disclosure validation** - Action button interactions and dynamic content loading
- **Security feature verification** - MED-006/MED-007 implementations in browser environment
- **Cross-browser compatibility testing** - Chrome, Firefox, Safari with performance metrics
- **Performance and visual regression testing** - Load times, memory usage, and UI consistency

## Directory Structure

```
tests/ui/
├── __init__.py                 # UI test package
├── README.md                   # This documentation
├── conftest.py                 # Pytest fixtures and configuration
├── playwright.config.py        # Playwright configuration management
├── run_tests.py               # Test runner script
├── test_basic_navigation.py    # Basic navigation and loading tests
├── test_role_selection.py      # Role-based UI testing (Story 2.6.2)
├── test_progressive_disclosure.py # Progressive disclosure testing (Story 2.6.3)
├── test_security_features.py   # Security feature UI validation (Story 2.6.4)
├── test_cross_browser.py       # Cross-browser and performance testing (Story 2.6.6)
├── fixtures/                   # Test data and scenarios
│   ├── __init__.py
│   ├── test_users.py          # User role test data
│   ├── mock_cwe_data.py       # Mock CWE data for testing
│   └── ui_scenarios.py        # Common interaction patterns
└── utils/                     # Test utilities
    ├── __init__.py
    ├── chainlit_helpers.py    # Chainlit-specific test utilities
    ├── role_helpers.py        # Role-based testing helpers
    └── screenshot_helpers.py  # Visual testing and screenshots
```

## Quick Start

### Prerequisites

1. **Poetry Environment**: Ensure Poetry dependencies are installed
   ```bash
   poetry install
   ```

2. **Playwright Browsers**: Install Playwright browsers
   ```bash
   poetry run playwright install
   ```

3. **System Dependencies** (optional, for full browser support):
   ```bash
   sudo poetry run playwright install-deps
   ```

4. **Running Application**: Start the Chainlit application
   ```bash
   poetry run chainlit run apps/chatbot/main.py
   ```

### Running Tests

#### Using the Test Runner (Recommended)

```bash
# Check prerequisites
python tests/ui/run_tests.py check

# Run basic navigation tests (opens browser window)  
python tests/ui/run_tests.py basic

# Run basic tests in headless mode
python tests/ui/run_tests.py basic --headless

# Run all UI tests
python tests/ui/run_tests.py all

# Test specific functionality areas
python tests/ui/run_tests.py role-based          # Role selection and role-based UI
python tests/ui/run_tests.py progressive         # Progressive disclosure features
python tests/ui/run_tests.py security --headless # Security features (MED-006/007)
python tests/ui/run_tests.py performance         # Performance benchmarking

# Test across all browsers (headless)
python tests/ui/run_tests.py cross-browser --headless

# Complete regression test suite
python tests/ui/run_tests.py regression

# Interactive mode for debugging
python tests/ui/run_tests.py interactive
```

#### Using Pytest Directly

```bash
# Run basic navigation tests
poetry run pytest tests/ui/test_basic_navigation.py -v

# Run with specific browser
poetry run pytest tests/ui/ --browser chromium --headed -v

# Run headless tests
poetry run pytest tests/ui/ --browser chromium --headless -v

# Run with screenshots on failure
poetry run pytest tests/ui/ --screenshot only-on-failure -v
```

## Test Configuration

### Environment Configuration

Tests can be configured for different environments:

- **local**: Development environment with visible browsers
- **ci**: CI/CD environment with headless browsers
- **staging**: Staging environment testing
- **production**: Production environment monitoring

```bash
# Create environment config file
python tests/ui/run_tests.py config --env local
```

### Browser Configuration

Supported browsers:
- **chromium**: Default, most stable
- **firefox**: Cross-browser testing
- **webkit**: Safari-equivalent testing

```bash
# Test specific browser
python tests/ui/run_tests.py basic --browser firefox
```

### Configuration Options

Environment variables for customization:

```bash
export CHAINLIT_BASE_URL="http://localhost:8000"    # Application URL
export PLAYWRIGHT_HEADLESS="false"                  # Show browser window
export PLAYWRIGHT_BROWSER="chromium"                # Browser choice
export PLAYWRIGHT_SCREENSHOT="only-on-failure"      # Screenshot mode
export PLAYWRIGHT_VIDEO="retain-on-failure"         # Video recording
export TEST_ENV="local"                             # Environment config
```

## Test Structure

### Test Organization

Tests are organized by functionality as per Story 2.6 implementation plan:

1. **Basic Navigation** (`test_basic_navigation.py`)
   - Application loading and startup
   - Interface element presence verification
   - Responsive design across viewport sizes
   - Performance validation and error handling

2. **Role-Based Testing** (`test_role_selection.py`) - **Story 2.6.2 Implementation**
   - Role selection interface testing for all 5 user roles (PSIRT, Developer, Academic, Bug Bounty, Product Manager)
   - Role-specific response formatting validation
   - Role context preservation across sessions and page refreshes
   - Role switching functionality with UI feedback validation
   - Performance testing of role operations

3. **Progressive Disclosure** (`test_progressive_disclosure.py`) - **Story 2.6.3 Implementation**
   - Action button interactions ("Tell Me More", "Show Consequences", etc.)
   - Dynamic content loading and state management
   - Button state management (enabled/disabled after click)
   - Loading indicators and content organization
   - Role-specific progressive action integration
   - Performance testing of progressive operations

4. **Security Feature Validation** (`test_security_features.py`) - **Story 2.6.4 Implementation**
   - Input sanitization testing (MED-007): XSS, SQL injection, prompt injection, path traversal
   - Session encryption validation (MED-006): Browser storage inspection, session isolation
   - CSRF protection testing for progressive disclosure actions
   - Security event logging and monitoring integration
   - Performance impact assessment of security features

5. **Cross-Browser Compatibility** (`test_cross_browser.py`) - **Story 2.6.6 Implementation**
   - Application loading across Chrome, Firefox, Safari
   - JavaScript compatibility and WebSocket connectivity
   - CSS feature support and accessibility testing
   - Performance metrics across browsers (load times, memory usage)
   - Mobile compatibility testing
   - Network condition simulation (slow 3G, offline behavior)

### Test Fixtures and Utilities

#### Chainlit Helpers (`utils/chainlit_helpers.py`)
- `ChainlitTestHelper`: Main helper class for Chainlit interactions
- `setup_test_environment()`: Initialize test environment
- `submit_query_and_get_response()`: Query submission utilities

#### Role Helpers (`utils/role_helpers.py`)
- `RoleTestHelper`: Role-specific test data and validation
- Test queries for each user role (PSIRT, Developer, Academic, etc.)
- Response format validation

#### Screenshot Helpers (`utils/screenshot_helpers.py`)
- `ScreenshotHelper`: Screenshot capture and management
- Visual regression testing utilities
- Baseline comparison functionality

#### Mock Data (`fixtures/mock_cwe_data.py`)
- `MockCWEDatabase`: Test CWE data without external dependencies
- Security test scenarios and malicious inputs
- Role-specific test scenarios

## Writing New Tests

### Basic Test Structure

```python
import pytest
from playwright.async_api import Page
from utils.chainlit_helpers import setup_test_environment

class TestMyFeature:
    @pytest.mark.asyncio
    async def test_my_functionality(self, page: Page, chainlit_base_url: str):
        # Set up test environment
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Test logic here
        await helper.submit_message("Test query")
        response = await helper.get_last_response()
        
        # Assertions
        assert len(response) > 0
```

### Role-Based Testing

```python
from utils.role_helpers import get_test_query_for_role, validate_role_response_format
from user.role_manager import UserRole

@pytest.mark.parametrize("role", [UserRole.PSIRT, UserRole.DEVELOPER])
@pytest.mark.asyncio
async def test_role_response_format(self, page: Page, chainlit_base_url: str, role):
    helper = await setup_test_environment(page, chainlit_base_url)
    
    # Select role (when role selection is implemented)
    await helper.simulate_user_role_selection(role.value)
    
    # Submit role-appropriate query
    query = get_test_query_for_role(role)
    await helper.submit_message(query)
    
    # Validate response format
    response = await helper.get_last_response()
    assert validate_role_response_format(response, role)
```

### Scenario-Based Testing

```python
from fixtures.ui_scenarios import ScenarioExecutor, get_scenario

@pytest.mark.asyncio
async def test_query_submission_scenario(self, page: Page, chainlit_base_url: str):
    scenario = get_scenario("query_submission")
    executor = ScenarioExecutor(page)
    
    result = await executor.execute_scenario(scenario, {
        "query": "Tell me about CWE-79"
    })
    
    assert result["success"]
```

## Debugging Tests

### Interactive Mode

Use interactive mode to debug test scenarios:

```bash
python tests/ui/run_tests.py interactive
```

This opens a browser window and pauses execution for manual inspection.

### Screenshots and Videos

Tests automatically capture:
- Screenshots on failure (`test-results/screenshots/`)
- Videos on failure (`test-results/videos/`)
- Traces for debugging (`test-results/traces/`)

### Debug Utilities

```python
# Take manual screenshot
await take_test_screenshot(page, "debug_checkpoint")

# Print page content
content = await page.content()
print(content)

# Inspect console messages
page.on("console", lambda msg: print(f"Console: {msg.text}"))
```

## Continuous Integration

### GitHub Actions Configuration

```yaml
- name: Install Playwright browsers
  run: poetry run playwright install --with-deps

- name: Run UI tests
  run: |
    poetry run pytest tests/ui/ \
      --browser chromium \
      --headless \
      --screenshot only-on-failure \
      --video retain-on-failure
```

### CI-Optimized Testing

```bash
# Fast smoke tests for CI
python tests/ui/run_tests.py basic --headless

# Full regression suite (longer)
python tests/ui/run_tests.py all --headless
```

## Performance Considerations

### Test Optimization

- Use `--headed` mode only for debugging
- Minimize `asyncio.sleep()` calls - use proper waits
- Reuse browser contexts when possible
- Run tests in parallel with `pytest-xdist`

### Resource Management

```bash
# Parallel test execution
poetry run pytest tests/ui/ -n 2  # 2 parallel processes

# Clean up old test artifacts
find test-results/ -type f -mtime +7 -delete
```

## Troubleshooting

### Common Issues

1. **Application not running**: Ensure Chainlit app is started on localhost:8000
2. **Browser not found**: Run `poetry run playwright install`  
3. **System dependencies**: Run `sudo playwright install-deps`
4. **Timeout errors**: Increase timeout values or check application performance

### Debug Commands

```bash
# Check Playwright installation
poetry run playwright --version

# List installed browsers  
poetry run playwright install --dry-run

# Test browser launch
poetry run python -c "from playwright.sync_api import sync_playwright; print('OK')"
```

### Environment Issues

Create debug environment file:
```bash
python tests/ui/run_tests.py config --env local
cat .env.test.local
```

## Future Enhancements

Planned additions as part of Story 2.6:

1. **Role Selection Testing**: Automated role switching and validation
2. **Progressive Disclosure**: Full action button interaction testing  
3. **Security Validation**: Input sanitization and CSRF testing
4. **Performance Monitoring**: Response time and resource usage metrics
5. **Visual Regression**: Baseline screenshot comparison
6. **Accessibility Testing**: Screen reader and keyboard navigation
7. **Mobile Testing**: Responsive design across device sizes

## Resources

- [Playwright Documentation](https://playwright.dev/python/)
- [pytest-playwright Plugin](https://github.com/microsoft/playwright-pytest)
- [Story 2.6 Implementation Plan](../../docs/plans/2.6.Interactive-UI-UX-Testing-Environment.md)
- [Story 2.6 Requirements](../../docs/stories/2.6.Interactive-UI-UX-Testing-Environment.md)