"""
Common UI interaction patterns and scenarios for testing.
Provides reusable interaction flows for different test types.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List

from playwright.async_api import Page


class InteractionType(Enum):
    """Types of UI interactions for testing."""

    NAVIGATION = "navigation"
    FORM_SUBMISSION = "form_submission"
    BUTTON_CLICK = "button_click"
    TEXT_INPUT = "text_input"
    ELEMENT_WAIT = "element_wait"
    VALIDATION = "validation"
    SCREENSHOT = "screenshot"


@dataclass
class UIAction:
    """Represents a single UI action in a test scenario."""

    action_type: InteractionType
    description: str
    selector: str = ""
    value: str = ""
    timeout: int = 10000
    optional: bool = False
    validation_fn: Callable[[Page], Awaitable[bool]] = None


@dataclass
class UIScenario:
    """Complete UI interaction scenario for testing."""

    name: str
    description: str
    actions: List[UIAction]
    setup_actions: List[UIAction] = None
    cleanup_actions: List[UIAction] = None
    expected_outcomes: List[str] = None


class CommonUIScenarios:
    """Collection of common UI interaction scenarios."""

    # Basic application navigation
    BASIC_NAVIGATION = UIScenario(
        name="basic_navigation",
        description="Navigate to the application and verify it loads",
        actions=[
            UIAction(
                action_type=InteractionType.NAVIGATION,
                description="Navigate to Chainlit application",
                value="http://localhost:8000",
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for application to load",
                selector="body, [data-testid='chainlit-app'], #root",
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Verify page title contains expected text",
            ),
        ],
        expected_outcomes=[
            "Application loads successfully",
            "Main UI elements are visible",
        ],
    )

    # Role selection workflow
    ROLE_SELECTION = UIScenario(
        name="role_selection",
        description="Select a user role in the application",
        actions=[
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for role selection interface",
                selector="[data-testid*='role'], button:has-text('PSIRT'), select",
            ),
            UIAction(
                action_type=InteractionType.BUTTON_CLICK,
                description="Click role selection button",
                selector="[data-testid='role-selector'], button:has-text('Select Role')",
            ),
            UIAction(
                action_type=InteractionType.BUTTON_CLICK,
                description="Select specific role",
                selector="button:has-text('{role}'), [data-testid='role-{role}']",
                value="{role}",  # Will be replaced with actual role
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Verify role selection is confirmed",
            ),
        ],
        expected_outcomes=[
            "Role is selected successfully",
            "UI adapts to selected role",
        ],
    )

    # Basic query submission
    QUERY_SUBMISSION = UIScenario(
        name="query_submission",
        description="Submit a query and wait for response",
        actions=[
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for input field",
                selector="input, textarea, [data-testid*='input']",
            ),
            UIAction(
                action_type=InteractionType.TEXT_INPUT,
                description="Enter query text",
                selector="input:visible, textarea:visible, [data-testid='message-input']",
                value="{query}",  # Will be replaced with actual query
            ),
            UIAction(
                action_type=InteractionType.BUTTON_CLICK,
                description="Submit query",
                selector="button[type='submit'], [data-testid='submit-button']",
                optional=True,  # Might use Enter key instead
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for response",
                selector="[data-testid*='response'], [data-testid*='message'], .response",
                timeout=30000,
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Validate response content",
            ),
        ],
        expected_outcomes=[
            "Query is submitted successfully",
            "Response is received and displayed",
        ],
    )

    # Progressive disclosure interaction
    PROGRESSIVE_DISCLOSURE = UIScenario(
        name="progressive_disclosure",
        description="Test progressive disclosure button interactions",
        setup_actions=[
            # Assumes query has been submitted and initial response received
        ],
        actions=[
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for progressive disclosure buttons",
                selector="button:has-text('Tell Me More'), button:has-text('Show'), [data-testid*='action-button']",
            ),
            UIAction(
                action_type=InteractionType.BUTTON_CLICK,
                description="Click progressive disclosure button",
                selector="button:has-text('{action}'), [data-testid='{action}-button']",
                value="{action}",  # Will be replaced with specific action
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for additional content to load",
                selector="[data-testid*='additional'], [data-testid*='expanded']",
                timeout=15000,
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Validate additional content is displayed",
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Verify button state changes (e.g., disabled)",
            ),
        ],
        expected_outcomes=[
            "Progressive disclosure button responds to click",
            "Additional content is loaded and displayed",
            "Button state updates appropriately",
        ],
    )

    # Security input testing
    SECURITY_INPUT_TESTING = UIScenario(
        name="security_input_testing",
        description="Test application behavior with malicious input",
        actions=[
            UIAction(
                action_type=InteractionType.TEXT_INPUT,
                description="Submit potentially malicious input",
                selector="input:visible, textarea:visible",
                value="{malicious_input}",  # Will be replaced with test payload
            ),
            UIAction(
                action_type=InteractionType.BUTTON_CLICK,
                description="Submit malicious input",
                selector="button[type='submit'], [data-testid='submit-button']",
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for response or error handling",
                selector="[data-testid*='response'], [data-testid*='error'], .error, .response",
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Verify input is properly sanitized",
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Verify no script execution or injection occurred",
            ),
        ],
        expected_outcomes=[
            "Malicious input is properly sanitized",
            "No code execution or injection occurs",
            "Appropriate error handling is displayed",
        ],
    )

    # Cross-browser compatibility test
    CROSS_BROWSER_COMPATIBILITY = UIScenario(
        name="cross_browser_compatibility",
        description="Test core functionality across different browsers",
        actions=[
            UIAction(
                action_type=InteractionType.NAVIGATION,
                description="Navigate to application",
                value="http://localhost:8000",
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Verify application loads",
                selector="body",
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Check browser-specific features work",
            ),
            UIAction(
                action_type=InteractionType.SCREENSHOT,
                description="Capture browser-specific rendering",
            ),
        ],
        expected_outcomes=[
            "Application loads in all supported browsers",
            "Core functionality works consistently",
            "UI renders correctly across browsers",
        ],
    )

    # Performance testing scenario
    PERFORMANCE_TESTING = UIScenario(
        name="performance_testing",
        description="Test application performance and responsiveness",
        actions=[
            UIAction(
                action_type=InteractionType.NAVIGATION,
                description="Navigate to application and measure load time",
                value="http://localhost:8000",
            ),
            UIAction(
                action_type=InteractionType.TEXT_INPUT,
                description="Submit query and measure response time",
                selector="input:visible, textarea:visible",
                value="Tell me about CWE-79",
            ),
            UIAction(
                action_type=InteractionType.ELEMENT_WAIT,
                description="Wait for response with timeout measurement",
                selector="[data-testid*='response']",
                timeout=30000,
            ),
            UIAction(
                action_type=InteractionType.VALIDATION,
                description="Validate response time is within acceptable limits",
            ),
        ],
        expected_outcomes=[
            "Page load time is under 3 seconds",
            "Query response time is under 10 seconds",
            "UI remains responsive during processing",
        ],
    )


class ScenarioExecutor:
    """Utility class for executing UI scenarios with Playwright."""

    def __init__(self, page: Page):
        self.page = page
        self.results = []

    async def execute_scenario(
        self, scenario: UIScenario, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Execute a complete UI scenario and return results."""
        if context is None:
            context = {}

        result = {
            "scenario_name": scenario.name,
            "success": True,
            "actions_completed": 0,
            "total_actions": len(scenario.actions),
            "errors": [],
            "execution_time": 0,
        }

        import time

        start_time = time.time()

        try:
            # Execute setup actions if any
            if scenario.setup_actions:
                await self._execute_actions(scenario.setup_actions, context, result)

            # Execute main actions
            await self._execute_actions(scenario.actions, context, result)

            # Execute cleanup actions if any
            if scenario.cleanup_actions:
                await self._execute_actions(scenario.cleanup_actions, context, result)

        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Scenario execution failed: {str(e)}")

        result["execution_time"] = time.time() - start_time
        self.results.append(result)
        return result

    async def _execute_actions(
        self, actions: List[UIAction], context: Dict[str, Any], result: Dict[str, Any]
    ):
        """Execute a list of UI actions."""
        for action in actions:
            try:
                await self._execute_action(action, context)
                result["actions_completed"] += 1
            except Exception as e:
                if not action.optional:
                    result["success"] = False
                    result["errors"].append(
                        f"Action '{action.description}' failed: {str(e)}"
                    )
                    raise
                else:
                    result["errors"].append(
                        f"Optional action '{action.description}' skipped: {str(e)}"
                    )

    async def _execute_action(self, action: UIAction, context: Dict[str, Any]):
        """Execute a single UI action."""
        # Replace context variables in selector and value
        selector = self._replace_context_variables(action.selector, context)
        value = self._replace_context_variables(action.value, context)

        if action.action_type == InteractionType.NAVIGATION:
            url = value or action.value
            await self.page.goto(url)

        elif action.action_type == InteractionType.ELEMENT_WAIT:
            await self.page.wait_for_selector(selector, timeout=action.timeout)

        elif action.action_type == InteractionType.TEXT_INPUT:
            element = self.page.locator(selector).first
            await element.clear()
            await element.fill(value)

        elif action.action_type == InteractionType.BUTTON_CLICK:
            element = self.page.locator(selector).first
            await element.click()

        elif action.action_type == InteractionType.VALIDATION:
            if action.validation_fn:
                result = await action.validation_fn(self.page)
                if not result:
                    raise Exception(f"Validation failed: {action.description}")

        elif action.action_type == InteractionType.SCREENSHOT:
            screenshot_name = f"{action.description.replace(' ', '_').lower()}"
            await self.page.screenshot(
                path=f"test-results/screenshots/{screenshot_name}.png"
            )

    def _replace_context_variables(self, text: str, context: Dict[str, Any]) -> str:
        """Replace context variables in text with actual values."""
        if not text:
            return text

        for key, value in context.items():
            placeholder = f"{{{key}}}"
            if placeholder in text:
                text = text.replace(placeholder, str(value))

        return text

    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of all scenario executions."""
        if not self.results:
            return {"total_scenarios": 0, "success_rate": 0}

        successful = sum(1 for r in self.results if r["success"])
        total_time = sum(r["execution_time"] for r in self.results)

        return {
            "total_scenarios": len(self.results),
            "successful_scenarios": successful,
            "failed_scenarios": len(self.results) - successful,
            "success_rate": successful / len(self.results) * 100,
            "total_execution_time": total_time,
            "average_execution_time": total_time / len(self.results),
            "results": self.results,
        }


# Utility functions
def get_scenario(name: str) -> UIScenario:
    """Get a UI scenario by name."""
    scenarios = {
        "basic_navigation": CommonUIScenarios.BASIC_NAVIGATION,
        "role_selection": CommonUIScenarios.ROLE_SELECTION,
        "query_submission": CommonUIScenarios.QUERY_SUBMISSION,
        "progressive_disclosure": CommonUIScenarios.PROGRESSIVE_DISCLOSURE,
        "security_input_testing": CommonUIScenarios.SECURITY_INPUT_TESTING,
        "cross_browser_compatibility": CommonUIScenarios.CROSS_BROWSER_COMPATIBILITY,
        "performance_testing": CommonUIScenarios.PERFORMANCE_TESTING,
    }
    return scenarios.get(name)


def create_custom_scenario(name: str, actions: List[UIAction]) -> UIScenario:
    """Create a custom UI scenario."""
    return UIScenario(
        name=name, description=f"Custom scenario: {name}", actions=actions
    )


async def execute_quick_test(
    page: Page, scenario_name: str, context: Dict[str, Any] = None
) -> bool:
    """Execute a quick test scenario and return success status."""
    scenario = get_scenario(scenario_name)
    if not scenario:
        return False

    executor = ScenarioExecutor(page)
    result = await executor.execute_scenario(scenario, context)
    return result["success"]
