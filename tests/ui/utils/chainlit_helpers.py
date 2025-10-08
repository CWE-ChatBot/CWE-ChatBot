"""
Helper utilities for Chainlit UI testing with Playwright.
Provides common operations for interacting with Chainlit interface.
"""

import asyncio
from typing import Dict

from playwright.async_api import Locator, Page


class ChainlitTestHelper:
    """Helper class for Chainlit-specific UI testing operations."""

    def __init__(self, page: Page, base_url: str = "http://localhost:8000"):
        self.page = page
        self.base_url = base_url

    async def navigate_to_app(self) -> None:
        """Navigate to the Chainlit application."""
        await self.page.goto(self.base_url)

    async def wait_for_chainlit_ready(self, timeout: int = 30000) -> None:
        """Wait for Chainlit application to be fully loaded and ready."""
        # Wait for the main Chainlit container to be present
        await self.page.wait_for_selector(
            '[data-testid="chainlit-app"], .chainlit-app, #root', timeout=timeout
        )

        # Wait for any loading indicators to disappear
        await self.page.wait_for_function(
            "() => !document.querySelector('.loading, [data-testid=\"loading\"]')",
            timeout=timeout,
        )

        # Additional wait for Chainlit-specific initialization
        await asyncio.sleep(1)

    async def submit_message(
        self, message: str, wait_for_response: bool = True
    ) -> None:
        """Submit a message through the Chainlit interface."""
        # Look for common input selectors in Chainlit
        input_selectors = [
            '[data-testid="message-input"]',
            '[placeholder*="message"], [placeholder*="question"], [placeholder*="query"]',
            'input[type="text"]:last-of-type',
            "textarea:last-of-type",
        ]

        message_input = None
        for selector in input_selectors:
            try:
                message_input = self.page.locator(selector).first
                if await message_input.is_visible():
                    break
            except:
                continue

        if not message_input:
            raise RuntimeError("Could not find message input field")

        # Clear and fill the input
        await message_input.clear()
        await message_input.fill(message)

        # Submit the message (try Enter key first, then look for submit button)
        try:
            await message_input.press("Enter")
        except:
            # Look for submit button as fallback
            submit_selectors = [
                '[data-testid="submit-button"]',
                'button[type="submit"]',
                'button:has-text("Send")',
                'button:has-text("Submit")',
            ]

            for selector in submit_selectors:
                try:
                    submit_btn = self.page.locator(selector).first
                    if await submit_btn.is_visible():
                        await submit_btn.click()
                        break
                except:
                    continue

        if wait_for_response:
            await self.wait_for_response()

    async def wait_for_response(self, timeout: int = 30000) -> None:
        """Wait for a response to appear after submitting a message."""
        # Wait for response indicators
        response_selectors = [
            '[data-testid="message-response"]',
            '[data-testid="bot-message"]',
            ".message.bot, .response, .ai-message",
        ]

        # Try each selector and wait for content to appear
        for selector in response_selectors:
            try:
                await self.page.wait_for_selector(selector, timeout=5000)
                # Wait for content to be populated
                await self.page.wait_for_function(
                    f"() => document.querySelector('{selector}')?.textContent?.trim()?.length > 0",
                    timeout=timeout,
                )
                return
            except:
                continue

        # Fallback: wait for any new text content to appear
        await asyncio.sleep(2)

    async def get_last_response(self) -> str:
        """Get the content of the last bot response."""
        response_selectors = [
            '[data-testid="message-response"]:last-child',
            '[data-testid="bot-message"]:last-child',
            ".message.bot:last-child, .response:last-child, .ai-message:last-child",
        ]

        for selector in response_selectors:
            try:
                element = self.page.locator(selector).first
                if await element.is_visible():
                    return await element.text_content() or ""
            except:
                continue

        return ""

    async def get_all_messages(self) -> list[Dict[str, str]]:
        """Get all messages in the conversation."""
        messages = []

        # Try to find message containers
        message_selectors = [".message", '[data-testid*="message"]', ".chat-message"]

        for selector in message_selectors:
            try:
                message_elements = await self.page.locator(selector).all()
                if message_elements:
                    for element in message_elements:
                        text = await element.text_content() or ""
                        classes = await element.get_attribute("class") or ""

                        # Determine message type based on classes or position
                        msg_type = "user" if "user" in classes.lower() else "bot"

                        if text.strip():
                            messages.append({"type": msg_type, "content": text.strip()})
                    break
            except:
                continue

        return messages

    async def click_action_button(self, button_text: str) -> None:
        """Click an action button (like progressive disclosure buttons)."""
        # Look for buttons with the specified text
        button_selectors = [
            f'button:has-text("{button_text}")',
            f'[data-testid*="{button_text.lower().replace(" ", "-")}-button"]',
            f'button[aria-label*="{button_text}"]',
        ]

        for selector in button_selectors:
            try:
                button = self.page.locator(selector).first
                if await button.is_visible() and await button.is_enabled():
                    await button.click()
                    return
            except:
                continue

        raise RuntimeError(f"Could not find or click button with text: {button_text}")

    async def wait_for_element(self, selector: str, timeout: int = 10000) -> Locator:
        """Wait for an element to appear and return its locator."""
        await self.page.wait_for_selector(selector, timeout=timeout)
        return self.page.locator(selector)

    async def take_screenshot(self, name: str) -> str:
        """Take a screenshot for debugging purposes."""
        screenshot_path = f"test-results/screenshots/{name}.png"
        await self.page.screenshot(path=screenshot_path, full_page=True)
        return screenshot_path

    async def simulate_user_role_selection(self, role: str) -> None:
        """Simulate selecting a user role in the interface."""
        # This will need to be implemented based on how role selection works
        # in the actual Chainlit interface

        role_selectors = [
            f'button:has-text("{role}")',
            f'[data-testid="role-{role.lower()}"]',
            f'option[value="{role}"]',
        ]

        for selector in role_selectors:
            try:
                element = self.page.locator(selector).first
                if await element.is_visible():
                    await element.click()
                    return
            except:
                continue

        # If no specific role selector found, might need to type in a field
        # This will be refined as we understand the actual UI implementation
        print(f"Warning: Could not find role selector for {role}")


# Helper functions for common operations
async def setup_test_environment(
    page: Page, base_url: str = "http://localhost:8000"
) -> ChainlitTestHelper:
    """Set up the test environment and return a configured helper."""
    helper = ChainlitTestHelper(page, base_url)
    await helper.navigate_to_app()
    await helper.wait_for_chainlit_ready()
    return helper


async def submit_query_and_get_response(helper: ChainlitTestHelper, query: str) -> str:
    """Submit a query and return the response content."""
    await helper.submit_message(query)
    return await helper.get_last_response()
