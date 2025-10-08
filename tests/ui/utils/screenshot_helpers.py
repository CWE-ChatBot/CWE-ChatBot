"""
Screenshot and visual regression testing utilities.
Provides helpers for capturing and comparing screenshots during testing.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from playwright.async_api import Page


class ScreenshotHelper:
    """Helper class for screenshot operations and visual regression testing."""

    def __init__(self, base_screenshot_dir: str = "test-results/screenshots"):
        self.base_dir = Path(base_screenshot_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Subdirectories for organization
        self.current_dir = self.base_dir / "current"
        self.baseline_dir = self.base_dir / "baseline"
        self.diff_dir = self.base_dir / "diffs"

        for dir_path in [self.current_dir, self.baseline_dir, self.diff_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    async def capture_screenshot(
        self,
        page: Page,
        name: str,
        full_page: bool = True,
        selector: Optional[str] = None,
    ) -> str:
        """Capture a screenshot of the page or a specific element."""

        # Clean the name for use as filename
        clean_name = self._clean_filename(name)
        screenshot_path = self.current_dir / f"{clean_name}.png"

        try:
            if selector:
                # Screenshot of specific element
                element = page.locator(selector)
                await element.screenshot(path=str(screenshot_path))
            else:
                # Full page or viewport screenshot
                await page.screenshot(path=str(screenshot_path), full_page=full_page)

            return str(screenshot_path)

        except Exception as e:
            print(f"Failed to capture screenshot '{name}': {e}")
            return ""

    async def capture_element_screenshot(
        self, page: Page, selector: str, name: str
    ) -> str:
        """Capture a screenshot of a specific element."""
        return await self.capture_screenshot(page, name, selector=selector)

    async def capture_viewport_screenshot(self, page: Page, name: str) -> str:
        """Capture a screenshot of just the viewport (not full page)."""
        return await self.capture_screenshot(page, name, full_page=False)

    def save_as_baseline(self, name: str) -> bool:
        """Save a current screenshot as the baseline for comparison."""
        clean_name = self._clean_filename(name)
        current_path = self.current_dir / f"{clean_name}.png"
        baseline_path = self.baseline_dir / f"{clean_name}.png"

        try:
            if current_path.exists():
                # Copy current to baseline
                baseline_path.write_bytes(current_path.read_bytes())
                return True
        except Exception as e:
            print(f"Failed to save baseline for '{name}': {e}")

        return False

    def compare_with_baseline(
        self, name: str, threshold: float = 0.1
    ) -> Dict[str, Any]:
        """Compare a current screenshot with its baseline."""
        clean_name = self._clean_filename(name)
        current_path = self.current_dir / f"{clean_name}.png"
        baseline_path = self.baseline_dir / f"{clean_name}.png"

        if not current_path.exists():
            return {"error": "Current screenshot not found", "match": False}

        if not baseline_path.exists():
            return {"error": "Baseline screenshot not found", "match": False}

        # Simple hash-based comparison for now
        # In a more sophisticated implementation, you might use image comparison libraries
        current_hash = self._get_file_hash(current_path)
        baseline_hash = self._get_file_hash(baseline_path)

        exact_match = current_hash == baseline_hash

        return {
            "match": exact_match,
            "current_hash": current_hash,
            "baseline_hash": baseline_hash,
            "current_path": str(current_path),
            "baseline_path": str(baseline_path),
        }

    def _get_file_hash(self, file_path: Path) -> str:
        """Get MD5 hash of a file."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""

    def _clean_filename(self, name: str) -> str:
        """Clean a name to be safe for use as a filename."""
        # Replace spaces and special characters
        clean = "".join(c for c in name if c.isalnum() or c in (" ", "-", "_")).rstrip()
        clean = clean.replace(" ", "_")
        return clean

    async def capture_page_state(self, page: Page, test_name: str) -> Dict[str, str]:
        """Capture comprehensive page state including screenshots and metadata."""
        clean_name = self._clean_filename(test_name)

        # Capture multiple screenshot types
        screenshots = {}

        # Full page screenshot
        full_page_path = await self.capture_screenshot(
            page, f"{clean_name}_full", full_page=True
        )
        if full_page_path:
            screenshots["full_page"] = full_page_path

        # Viewport screenshot
        viewport_path = await self.capture_screenshot(
            page, f"{clean_name}_viewport", full_page=False
        )
        if viewport_path:
            screenshots["viewport"] = viewport_path

        # Capture page metadata
        try:
            title = await page.title()
            url = page.url
            viewport_size = await page.evaluate(
                "() => ({width: window.innerWidth, height: window.innerHeight})"
            )
        except:
            title = "Unknown"
            url = "Unknown"
            viewport_size = {"width": 0, "height": 0}

        # Save metadata
        metadata = {
            "test_name": test_name,
            "title": title,
            "url": url,
            "viewport_size": viewport_size,
            "screenshots": screenshots,
        }

        metadata_path = self.current_dir / f"{clean_name}_metadata.json"
        try:
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"Failed to save metadata for '{test_name}': {e}")

        return screenshots

    def clean_old_screenshots(self, days: int = 7) -> None:
        """Clean up old screenshots older than specified days."""
        import time

        cutoff_time = time.time() - (days * 24 * 60 * 60)

        for directory in [self.current_dir, self.diff_dir]:
            try:
                for file_path in directory.glob("*"):
                    if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                        file_path.unlink()
            except Exception as e:
                print(f"Error cleaning screenshots from {directory}: {e}")


# Utility functions for common screenshot operations
async def take_test_screenshot(
    page: Page, name: str, helper: Optional[ScreenshotHelper] = None
) -> str:
    """Take a screenshot with a default helper if none provided."""
    if helper is None:
        helper = ScreenshotHelper()

    return await helper.capture_screenshot(page, name)


async def capture_ui_state_for_role(
    page: Page, role_name: str, helper: Optional[ScreenshotHelper] = None
) -> Dict[str, str]:
    """Capture UI state specifically for role-based testing."""
    if helper is None:
        helper = ScreenshotHelper()

    return await helper.capture_page_state(page, f"role_{role_name}_ui_state")


async def capture_progressive_disclosure_state(
    page: Page, action_name: str, helper: Optional[ScreenshotHelper] = None
) -> str:
    """Capture screenshot for progressive disclosure testing."""
    if helper is None:
        helper = ScreenshotHelper()

    return await helper.capture_screenshot(page, f"progressive_{action_name}")


# Visual regression testing helpers
class VisualRegressionTest:
    """Helper for visual regression testing workflows."""

    def __init__(self, screenshot_helper: Optional[ScreenshotHelper] = None):
        self.helper = screenshot_helper or ScreenshotHelper()

    async def assert_visual_match(
        self, page: Page, test_name: str, threshold: float = 0.1
    ) -> bool:
        """Assert that current page matches baseline screenshot."""
        # Capture current screenshot
        await self.helper.capture_screenshot(page, test_name)

        # Compare with baseline
        comparison = self.helper.compare_with_baseline(test_name, threshold)

        if "error" in comparison:
            print(f"Visual regression test failed: {comparison['error']}")
            return False

        if not comparison["match"]:
            print("Visual regression test failed: Screenshot does not match baseline")
            print(f"Current: {comparison['current_path']}")
            print(f"Baseline: {comparison['baseline_path']}")
            return False

        return True

    async def update_baseline(self, page: Page, test_name: str) -> bool:
        """Update baseline screenshot for a test."""
        await self.helper.capture_screenshot(page, test_name)
        return self.helper.save_as_baseline(test_name)
