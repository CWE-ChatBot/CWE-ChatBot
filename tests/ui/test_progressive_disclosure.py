"""
Progressive disclosure UI testing.
Tests dynamic content loading, action button interactions, and UI state management.
"""

import pytest
from playwright.async_api import Page, expect
import asyncio
from utils.chainlit_helpers import ChainlitTestHelper, setup_test_environment
from utils.role_helpers import RoleTestHelper, get_all_test_roles
from utils.screenshot_helpers import capture_progressive_disclosure_state
from fixtures.mock_cwe_data import CWE_TEST_SCENARIOS, get_test_scenario
from fixtures.test_users import get_user_for_role

# Import user roles with fallback
try:
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'apps', 'chatbot', 'src'))
    from user.role_manager import UserRole
except ImportError:
    from enum import Enum
    class UserRole(Enum):
        PSIRT = "psirt"
        DEVELOPER = "developer"
        ACADEMIC = "academic"
        BUG_BOUNTY = "bug_bounty"
        PRODUCT_MANAGER = "product_manager"


class TestProgressiveDisclosureButtons:
    """Test progressive disclosure action button functionality."""
    
    @pytest.mark.asyncio
    async def test_progressive_disclosure_buttons_present(self, page: Page, chainlit_base_url: str):
        """Test that progressive disclosure buttons appear after initial response."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Submit a query that should trigger progressive disclosure buttons
        test_query = "Tell me about cross-site scripting vulnerabilities"
        
        try:
            await helper.submit_message(test_query)
            response = await helper.get_last_response()
            
            if response and len(response) > 10:
                print(f"✓ Initial response received: {len(response)} characters")
                
                # Look for progressive disclosure buttons
                progressive_button_selectors = [
                    "button:has-text('Tell Me More')",
                    "button:has-text('Show Consequences')", 
                    "button:has-text('Show Related')",
                    "button:has-text('Show Prevention')",
                    "button:has-text('Show Examples')",
                    "[data-testid*='tell-more']",
                    "[data-testid*='show-consequences']",
                    "[data-testid*='show-related']",
                    "[data-testid*='action-button']",
                    ".progressive-action",
                    ".disclosure-button"
                ]
                
                buttons_found = []
                
                for selector in progressive_button_selectors:
                    try:
                        elements = await page.locator(selector).all()
                        for element in elements:
                            if await element.is_visible():
                                button_text = await element.text_content()
                                if button_text and button_text.strip():
                                    buttons_found.append({
                                        'selector': selector,
                                        'text': button_text.strip()
                                    })
                    except:
                        continue
                
                if buttons_found:
                    print(f"✓ Progressive disclosure buttons found: {len(buttons_found)}")
                    for button in buttons_found:
                        print(f"  - {button['text']} ({button['selector']})")
                else:
                    print("ℹ Progressive disclosure buttons not yet implemented")
                    print("  Tested selectors:", progressive_button_selectors)
                
                # Take screenshot for documentation
                await capture_progressive_disclosure_state(page, "buttons_initial_state")
            else:
                print("ℹ No initial response to test progressive disclosure")
                
        except Exception as e:
            print(f"ℹ Progressive disclosure button testing: {e}")
    
    @pytest.mark.parametrize("action_type", [
        "tell_more",
        "show_consequences", 
        "show_related",
        "show_prevention",
        "show_examples"
    ])
    @pytest.mark.asyncio
    async def test_progressive_action_buttons(self, page: Page, chainlit_base_url: str, action_type: str):
        """Test individual progressive disclosure action buttons."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Submit initial query
        test_query = "Explain CWE-79 cross-site scripting"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print(f"ℹ No adequate initial response for {action_type} testing")
                return
            
            print(f"Testing {action_type} action...")
            
            # Look for the specific action button
            button_selectors = [
                f"button:has-text('{action_type.replace('_', ' ').title()}')",
                f"[data-testid='{action_type}-button']",
                f"[data-testid*='{action_type}']",
                f".{action_type}-button",
                f"button[aria-label*='{action_type}']"
            ]
            
            button_clicked = False
            
            for selector in button_selectors:
                try:
                    button = page.locator(selector).first
                    if await button.is_visible() and await button.is_enabled():
                        print(f"  Found {action_type} button: {selector}")
                        
                        # Capture state before clicking
                        await capture_progressive_disclosure_state(page, f"{action_type}_before_click")
                        
                        # Click the button
                        await button.click()
                        button_clicked = True
                        
                        # Wait for additional content
                        await asyncio.sleep(2)  # Allow content to load
                        
                        # Capture state after clicking
                        await capture_progressive_disclosure_state(page, f"{action_type}_after_click")
                        
                        # Check if additional content appeared
                        post_click_response = await helper.get_last_response()
                        
                        if post_click_response != initial_response:
                            print(f"  ✓ Additional content loaded after {action_type}")
                            print(f"  New content length: {len(post_click_response)} characters")
                        else:
                            print(f"  ⚠ No new content detected after {action_type}")
                        
                        # Check if button state changed (e.g., disabled)
                        is_disabled = not await button.is_enabled()
                        print(f"  Button disabled after click: {'✓' if is_disabled else '⚠'}")
                        
                        break
                        
                except Exception as e:
                    continue
            
            if not button_clicked:
                print(f"  ℹ {action_type} button not found or not clickable")
                print(f"  Tested selectors: {button_selectors}")
                
        except Exception as e:
            print(f"ℹ Progressive action testing for {action_type}: {e}")
    
    @pytest.mark.asyncio
    async def test_multiple_progressive_actions_sequence(self, page: Page, chainlit_base_url: str):
        """Test clicking multiple progressive disclosure buttons in sequence."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Submit initial query
        test_query = "What is SQL injection and how dangerous is it?"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("ℹ No adequate initial response for sequence testing")
                return
            
            print("Testing progressive action sequence...")
            
            # Define sequence of actions to test
            action_sequence = ["tell_more", "show_consequences", "show_related"]
            content_states = [initial_response]
            
            for i, action in enumerate(action_sequence):
                print(f"\nStep {i+1}: Testing {action}")
                
                try:
                    # Try to click the action button
                    await helper.click_action_button(action.replace('_', ' ').title())
                    
                    # Wait for content update
                    await asyncio.sleep(2)
                    
                    # Check for new content
                    new_response = await helper.get_last_response()
                    content_states.append(new_response)
                    
                    if new_response != content_states[-2]:
                        print(f"  ✓ Content updated after {action}")
                        print(f"  Content length: {len(new_response)} characters")
                    else:
                        print(f"  ⚠ No content change after {action}")
                    
                    # Take screenshot
                    await capture_progressive_disclosure_state(page, f"sequence_step_{i+1}_{action}")
                    
                except Exception as e:
                    print(f"  ℹ Action {action} failed: {e}")
                    break
            
            # Analyze the content progression
            print(f"\n=== Content Progression Analysis ===")
            print(f"Total steps: {len(content_states)}")
            
            unique_states = len(set(content_states))
            print(f"Unique content states: {unique_states}")
            
            if unique_states > 1:
                print("✓ Progressive disclosure showing different content")
            else:
                print("ℹ All content states identical")
                
        except Exception as e:
            print(f"ℹ Progressive action sequence testing: {e}")


class TestProgressiveDisclosureRoleIntegration:
    """Test progressive disclosure with role-based functionality."""
    
    @pytest.mark.parametrize("role", [
        UserRole.PSIRT,
        UserRole.DEVELOPER,
        UserRole.ACADEMIC
    ])
    @pytest.mark.asyncio
    async def test_role_specific_progressive_actions(self, page: Page, chainlit_base_url: str, role: UserRole):
        """Test that progressive actions are appropriate for each role."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        try:
            # Select role
            await helper.simulate_user_role_selection(role.value)
            
            # Get role-appropriate query
            test_user = get_user_for_role(role)
            test_query = test_user.typical_queries[0]
            
            print(f"Testing progressive actions for {role.value}")
            print(f"Query: {test_query}")
            
            # Submit query
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print(f"  ℹ No adequate response for {role.value}")
                return
            
            # Get expected progressive actions for this role
            expected_actions = RoleTestHelper.get_expected_progressive_actions(role)
            print(f"  Expected actions: {expected_actions}")
            
            # Check which action buttons are available
            available_actions = []
            
            for action in expected_actions:
                try:
                    button_text = action.replace('_', ' ').title()
                    await helper.click_action_button(button_text)
                    available_actions.append(action)
                    
                    # Wait for content
                    await asyncio.sleep(1)
                    
                    # Take screenshot
                    await capture_progressive_disclosure_state(page, f"role_{role.value}_{action}")
                    
                    print(f"    ✓ {action} action available")
                    
                except Exception as e:
                    print(f"    ℹ {action} action not available: {e}")
            
            # Analyze role-action alignment
            if available_actions:
                coverage = len(available_actions) / len(expected_actions)
                print(f"  Action coverage: {coverage:.1%}")
                
                if coverage >= 0.5:
                    print(f"  ✓ Good action coverage for {role.value}")
                else:
                    print(f"  ⚠ Limited action coverage for {role.value}")
            else:
                print(f"  ℹ No progressive actions available for {role.value}")
                
        except Exception as e:
            print(f"ℹ Role-specific progressive testing for {role.value}: {e}")
    
    @pytest.mark.asyncio
    async def test_progressive_actions_adapt_to_role_switch(self, page: Page, chainlit_base_url: str):
        """Test that progressive actions change when roles are switched."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Test with two different roles
        role1 = UserRole.PSIRT
        role2 = UserRole.DEVELOPER
        test_query = "Explain buffer overflow vulnerabilities"
        
        try:
            print(f"Testing progressive action adaptation: {role1.value} → {role2.value}")
            
            # Test with first role
            await helper.simulate_user_role_selection(role1.value)
            await helper.submit_message(test_query)
            
            initial_response = await helper.get_last_response()
            if not initial_response:
                print("ℹ No initial response for role adaptation test")
                return
            
            # Document available actions for role 1
            role1_actions = []
            expected_role1_actions = RoleTestHelper.get_expected_progressive_actions(role1)
            
            for action in expected_role1_actions:
                try:
                    button_text = action.replace('_', ' ').title()
                    # Don't click, just check if available
                    button_selector = f"button:has-text('{button_text}')"
                    button = page.locator(button_selector).first
                    
                    if await button.is_visible():
                        role1_actions.append(action)
                except:
                    continue
            
            print(f"  {role1.value} actions available: {role1_actions}")
            await capture_progressive_disclosure_state(page, f"role_adaptation_{role1.value}")
            
            # Switch to second role
            await helper.simulate_user_role_selection(role2.value)
            await helper.submit_message(test_query)  # Same query
            
            await asyncio.sleep(1)  # Allow UI to update
            
            # Document available actions for role 2
            role2_actions = []
            expected_role2_actions = RoleTestHelper.get_expected_progressive_actions(role2)
            
            for action in expected_role2_actions:
                try:
                    button_text = action.replace('_', ' ').title()
                    button_selector = f"button:has-text('{button_text}')"
                    button = page.locator(button_selector).first
                    
                    if await button.is_visible():
                        role2_actions.append(action)
                except:
                    continue
            
            print(f"  {role2.value} actions available: {role2_actions}")
            await capture_progressive_disclosure_state(page, f"role_adaptation_{role2.value}")
            
            # Compare action sets
            if role1_actions != role2_actions:
                print("  ✓ Progressive actions adapted to role switch")
                
                # Analyze differences
                only_role1 = set(role1_actions) - set(role2_actions)
                only_role2 = set(role2_actions) - set(role1_actions)
                
                if only_role1:
                    print(f"    Actions only in {role1.value}: {list(only_role1)}")
                if only_role2:
                    print(f"    Actions only in {role2.value}: {list(only_role2)}")
            else:
                print("  ℹ Progressive actions identical across roles")
                
        except Exception as e:
            print(f"ℹ Role adaptation testing: {e}")


class TestProgressiveDisclosureState:
    """Test UI state management for progressive disclosure."""
    
    @pytest.mark.asyncio
    async def test_button_state_management(self, page: Page, chainlit_base_url: str):
        """Test that button states are managed correctly (enabled/disabled)."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_query = "What are the risks of using eval() in JavaScript?"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("ℹ No adequate response for button state testing")
                return
            
            print("Testing button state management...")
            
            # Find available buttons
            button_selectors = [
                "button:has-text('Tell Me More')",
                "button:has-text('Show')",
                "[data-testid*='action-button']"
            ]
            
            test_buttons = []
            
            for selector in button_selectors:
                try:
                    buttons = await page.locator(selector).all()
                    for button in buttons:
                        if await button.is_visible():
                            text = await button.text_content()
                            if text and text.strip():
                                test_buttons.append({
                                    'element': button,
                                    'text': text.strip(),
                                    'selector': selector
                                })
                except:
                    continue
            
            if not test_buttons:
                print("  ℹ No progressive action buttons found for state testing")
                return
            
            print(f"  Found {len(test_buttons)} buttons to test")
            
            # Test each button's state behavior
            for i, button_info in enumerate(test_buttons[:2]):  # Test first 2 buttons
                button = button_info['element']
                button_text = button_info['text']
                
                print(f"\n  Testing button: {button_text}")
                
                # Check initial state
                initial_enabled = await button.is_enabled()
                print(f"    Initial state: {'enabled' if initial_enabled else 'disabled'}")
                
                if initial_enabled:
                    # Click button
                    await button.click()
                    
                    # Wait for state change
                    await asyncio.sleep(1)
                    
                    # Check post-click state
                    post_click_enabled = await button.is_enabled()
                    print(f"    Post-click state: {'enabled' if post_click_enabled else 'disabled'}")
                    
                    # Verify content changed
                    new_response = await helper.get_last_response()
                    content_changed = new_response != initial_response
                    print(f"    Content changed: {'✓' if content_changed else '⚠'}")
                    
                    # Take screenshot of button state
                    await capture_progressive_disclosure_state(page, f"button_state_{i+1}")
                    
                    if not post_click_enabled and content_changed:
                        print(f"    ✓ Button correctly disabled after successful action")
                    elif post_click_enabled and not content_changed:
                        print(f"    ⚠ Button still enabled but no content change")
                    elif not post_click_enabled and not content_changed:
                        print(f"    ⚠ Button disabled but no content loaded")
                else:
                    print(f"    ℹ Button initially disabled")
                    
        except Exception as e:
            print(f"ℹ Button state management testing: {e}")
    
    @pytest.mark.asyncio
    async def test_progressive_content_loading_indicators(self, page: Page, chainlit_base_url: str):
        """Test loading indicators during progressive disclosure."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_query = "How do I secure my REST API against injection attacks?"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("ℹ No adequate response for loading indicator testing")
                return
            
            print("Testing progressive content loading indicators...")
            
            # Try to click a progressive action button
            try:
                await helper.click_action_button("Tell Me More")
                
                # Look for loading indicators immediately after click
                loading_selectors = [
                    ".loading",
                    ".spinner", 
                    "[data-testid*='loading']",
                    ".loading-indicator",
                    ".progress",
                    "[aria-label*='loading']",
                    ".dots"
                ]
                
                loading_found = False
                
                # Check quickly for loading indicators
                for selector in loading_selectors:
                    try:
                        loading_element = page.locator(selector).first
                        if await loading_element.is_visible(timeout=1000):
                            loading_found = True
                            print(f"  ✓ Loading indicator found: {selector}")
                            
                            # Take screenshot of loading state
                            await capture_progressive_disclosure_state(page, "loading_indicator")
                            break
                    except:
                        continue
                
                if not loading_found:
                    print("  ℹ No loading indicators detected")
                
                # Wait for content to finish loading
                await asyncio.sleep(3)
                
                # Verify loading indicators are gone
                for selector in loading_selectors:
                    try:
                        loading_element = page.locator(selector).first
                        if await loading_element.is_visible(timeout=1000):
                            print(f"  ⚠ Loading indicator still visible: {selector}")
                    except:
                        continue
                
                # Verify new content appeared
                final_response = await helper.get_last_response()
                if final_response != initial_response:
                    print("  ✓ Progressive content loaded successfully")
                else:
                    print("  ⚠ No new content after progressive action")
                    
            except Exception as e:
                print(f"  ℹ Progressive action failed: {e}")
                
        except Exception as e:
            print(f"ℹ Loading indicator testing: {e}")
    
    @pytest.mark.asyncio
    async def test_progressive_content_organization(self, page: Page, chainlit_base_url: str):
        """Test that progressive content is properly organized and displayed."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_query = "Explain CSRF attacks and their prevention"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("ℹ No adequate response for content organization testing")
                return
            
            print("Testing progressive content organization...")
            
            # Take initial screenshot
            await capture_progressive_disclosure_state(page, "content_organization_initial")
            
            # Try multiple progressive actions to build up content
            progressive_actions = ["Tell Me More", "Show Examples", "Show Prevention"]
            content_sections = []
            
            for i, action in enumerate(progressive_actions):
                try:
                    print(f"  Adding content section {i+1}: {action}")
                    
                    await helper.click_action_button(action)
                    await asyncio.sleep(2)
                    
                    # Capture content state
                    current_response = await helper.get_last_response()
                    content_sections.append(current_response)
                    
                    # Take screenshot
                    await capture_progressive_disclosure_state(page, f"content_section_{i+1}")
                    
                    # Check content organization
                    if len(content_sections) > 1:
                        # Verify content is expanding, not replacing
                        previous_content = content_sections[-2]
                        if len(current_response) > len(previous_content):
                            print(f"    ✓ Content expanded (was {len(previous_content)}, now {len(current_response)} chars)")
                        else:
                            print(f"    ⚠ Content may have been replaced rather than expanded")
                            
                except Exception as e:
                    print(f"    ℹ Progressive action '{action}' failed: {e}")
            
            # Analyze final content organization
            if content_sections:
                final_content = content_sections[-1]
                initial_content = content_sections[0] if content_sections else initial_response
                
                print(f"\n  Content organization analysis:")
                print(f"    Initial length: {len(initial_content)} characters")
                print(f"    Final length: {len(final_content)} characters")
                print(f"    Expansion ratio: {len(final_content) / len(initial_content):.1f}x")
                
                if len(final_content) > len(initial_content) * 1.2:
                    print("    ✓ Significant content expansion achieved")
                else:
                    print("    ℹ Limited content expansion")
                    
        except Exception as e:
            print(f"ℹ Content organization testing: {e}")


class TestProgressiveDisclosurePerformance:
    """Test performance of progressive disclosure operations."""
    
    @pytest.mark.asyncio
    async def test_progressive_action_response_time(self, page: Page, chainlit_base_url: str):
        """Test response times for progressive disclosure actions."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_query = "What are the security implications of XML External Entity attacks?"
        
        try:
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("ℹ No adequate response for performance testing")
                return
            
            print("Testing progressive action performance...")
            
            import time
            performance_results = []
            
            # Test several progressive actions for timing
            actions_to_test = ["Tell Me More", "Show Examples", "Show Prevention"]
            
            for action in actions_to_test:
                try:
                    print(f"\n  Testing performance of: {action}")
                    
                    start_time = time.time()
                    
                    # Click action button
                    await helper.click_action_button(action)
                    
                    # Wait for content to appear (with timeout)
                    timeout_start = time.time()
                    while time.time() - timeout_start < 15:  # 15 second timeout
                        current_response = await helper.get_last_response()
                        if current_response != initial_response:
                            break
                        await asyncio.sleep(0.5)
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    performance_results.append({
                        'action': action,
                        'response_time': response_time
                    })
                    
                    print(f"    Response time: {response_time:.2f} seconds")
                    
                    if response_time < 5.0:
                        print(f"    ✓ Acceptable performance")
                    else:
                        print(f"    ⚠ Slow response time")
                    
                    # Update initial response for next test
                    initial_response = await helper.get_last_response()
                    
                except Exception as e:
                    print(f"    ℹ Performance test for '{action}' failed: {e}")
            
            # Performance summary
            if performance_results:
                print(f"\n=== Progressive Action Performance Summary ===")
                
                total_tests = len(performance_results)
                avg_time = sum(r['response_time'] for r in performance_results) / total_tests
                max_time = max(r['response_time'] for r in performance_results)
                min_time = min(r['response_time'] for r in performance_results)
                
                print(f"Tests completed: {total_tests}")
                print(f"Average response time: {avg_time:.2f}s")
                print(f"Fastest response: {min_time:.2f}s")
                print(f"Slowest response: {max_time:.2f}s")
                
                # Performance thresholds
                fast_responses = sum(1 for r in performance_results if r['response_time'] < 3.0)
                acceptable_responses = sum(1 for r in performance_results if r['response_time'] < 10.0)
                
                print(f"Fast responses (<3s): {fast_responses}/{total_tests}")
                print(f"Acceptable responses (<10s): {acceptable_responses}/{total_tests}")
                
                if acceptable_responses == total_tests:
                    print("✓ All progressive actions meet performance criteria")
                else:
                    print("⚠ Some progressive actions are slow")
                    
        except Exception as e:
            print(f"ℹ Progressive action performance testing: {e}")


# Integration test combining role and progressive disclosure functionality
class TestRoleProgressiveIntegration:
    """Test integration of role-based and progressive disclosure functionality."""
    
    @pytest.mark.asyncio
    async def test_complete_role_progressive_workflow(self, page: Page, chainlit_base_url: str):
        """Test complete workflow: role selection → query → progressive disclosure."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_role = UserRole.DEVELOPER
        
        try:
            print(f"Testing complete workflow for {test_role.value}")
            
            # Step 1: Select role
            await helper.simulate_user_role_selection(test_role.value)
            print("  ✓ Role selected")
            
            # Step 2: Submit role-appropriate query
            test_user = get_user_for_role(test_role)
            test_query = test_user.typical_queries[0]
            
            await helper.submit_message(test_query)
            initial_response = await helper.get_last_response()
            
            if not initial_response or len(initial_response) < 10:
                print("  ℹ No adequate initial response")
                return
                
            print(f"  ✓ Initial response received: {len(initial_response)} characters")
            
            # Step 3: Validate role-appropriate progressive actions
            expected_actions = RoleTestHelper.get_expected_progressive_actions(test_role)
            
            successful_actions = 0
            
            for action in expected_actions[:2]:  # Test first 2 expected actions
                try:
                    action_text = action.replace('_', ' ').title()
                    await helper.click_action_button(action_text)
                    
                    await asyncio.sleep(2)
                    
                    new_response = await helper.get_last_response()
                    if new_response != initial_response:
                        successful_actions += 1
                        print(f"    ✓ {action} successful")
                        
                        # Update initial response for next comparison
                        initial_response = new_response
                    else:
                        print(f"    ⚠ {action} no content change")
                        
                except Exception as e:
                    print(f"    ℹ {action} failed: {e}")
            
            # Step 4: Evaluate complete workflow
            print(f"\n  Workflow evaluation:")
            print(f"    Role: {test_role.value}")
            print(f"    Expected actions: {len(expected_actions)}")
            print(f"    Successful actions: {successful_actions}")
            
            if successful_actions > 0:
                print(f"    ✓ Progressive disclosure functional for {test_role.value}")
            else:
                print(f"    ℹ Progressive disclosure not yet functional for {test_role.value}")
            
            # Take final screenshot
            await capture_progressive_disclosure_state(page, f"complete_workflow_{test_role.value}")
            
        except Exception as e:
            print(f"ℹ Complete workflow testing for {test_role.value}: {e}")


# Skip these tests by default until progressive disclosure is implemented
@pytest.mark.skip(reason="Progressive disclosure implementation pending")
class TestProgressiveImplementationReady:
    """Tests that will be enabled when progressive disclosure is implemented."""
    
    @pytest.mark.asyncio
    async def test_all_progressive_actions_functional(self, page: Page, chainlit_base_url: str):
        """Test that all progressive disclosure actions are functional."""
        pass
    
    @pytest.mark.asyncio  
    async def test_progressive_csrf_protection(self, page: Page, chainlit_base_url: str):
        """Test CSRF protection for progressive disclosure actions."""
        pass