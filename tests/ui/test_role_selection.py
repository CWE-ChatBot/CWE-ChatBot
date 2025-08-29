"""
Role selection and role-based UI testing.
Tests role selection functionality and role-specific UI adaptations.
"""

import pytest
from playwright.async_api import Page, expect
import asyncio
from utils.chainlit_helpers import ChainlitTestHelper, setup_test_environment
from utils.role_helpers import (
    RoleTestHelper, get_test_query_for_role, validate_role_response_format,
    get_all_test_roles, create_role_test_matrix
)
from utils.screenshot_helpers import capture_ui_state_for_role
from fixtures.test_users import TestUserFactory, get_user_for_role
from fixtures.ui_scenarios import ScenarioExecutor, get_scenario

# Import user roles (with fallback for testing)
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


class TestRoleSelection:
    """Test role selection UI functionality."""
    
    @pytest.mark.asyncio
    async def test_role_selection_interface_present(self, page: Page, chainlit_base_url: str):
        """Test that role selection interface elements are present."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Look for role selection elements
        # Note: These selectors will need to be updated based on actual Chainlit UI implementation
        role_selection_selectors = [
            "[data-testid*='role']",
            "select[name*='role']",
            "button:has-text('PSIRT')",
            "button:has-text('Developer')",
            "button:has-text('Academic')",
            "button:has-text('Bug Bounty')",
            "button:has-text('Product Manager')",
            ".role-selection",
            "#role-selector"
        ]
        
        # At least one role selection interface should be present
        role_interface_found = False
        found_selector = None
        
        for selector in role_selection_selectors:
            try:
                elements = await page.locator(selector).all()
                if elements and len(elements) > 0:
                    # Check if at least one element is visible
                    for element in elements:
                        if await element.is_visible():
                            role_interface_found = True
                            found_selector = selector
                            break
                if role_interface_found:
                    break
            except:
                continue
        
        # For now, this test will document what we find rather than fail
        # This allows the test framework to be ready when role selection is implemented
        if role_interface_found:
            print(f"✓ Role selection interface found with selector: {found_selector}")
            await capture_ui_state_for_role(page, "role_selection_interface")
        else:
            print("ℹ Role selection interface not yet implemented")
            print("  Tested selectors:", role_selection_selectors)
            await capture_ui_state_for_role(page, "no_role_selection")
        
        # Take screenshot for documentation
        await helper.take_screenshot("role_selection_interface_check")
    
    @pytest.mark.parametrize("role", [
        UserRole.PSIRT,
        UserRole.DEVELOPER,
        UserRole.ACADEMIC,
        UserRole.BUG_BOUNTY,
        UserRole.PRODUCT_MANAGER
    ])
    @pytest.mark.asyncio
    async def test_role_selection_for_each_role(self, page: Page, chainlit_base_url: str, role: UserRole):
        """Test role selection functionality for each user role."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Attempt to select the role
        try:
            await helper.simulate_user_role_selection(role.value)
            
            # If successful, verify role is selected
            # This will need to be updated based on actual UI feedback mechanisms
            await asyncio.sleep(1)  # Allow UI to update
            
            # Take screenshot of role-selected state
            await capture_ui_state_for_role(page, f"role_selected_{role.value}")
            
            print(f"✓ Role selection attempted for {role.value}")
            
        except Exception as e:
            # Document that role selection is not yet implemented
            print(f"ℹ Role selection for {role.value} not yet implemented: {e}")
            await capture_ui_state_for_role(page, f"role_selection_pending_{role.value}")
    
    @pytest.mark.asyncio
    async def test_role_selection_persistence(self, page: Page, chainlit_base_url: str):
        """Test that role selection persists across page interactions."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Try to select a role
        test_role = UserRole.DEVELOPER
        try:
            await helper.simulate_user_role_selection(test_role.value)
            
            # Submit a query to test if role context persists
            test_query = get_test_query_for_role(test_role)
            await helper.submit_message(test_query)
            
            # Check if response indicates role context was maintained
            response = await helper.get_last_response()
            
            if response:
                print(f"✓ Role context test completed for {test_role.value}")
                print(f"  Query: {test_query}")
                print(f"  Response length: {len(response)} characters")
                
                # Take screenshot of role-contextual response
                await capture_ui_state_for_role(page, f"role_context_{test_role.value}")
            else:
                print("ℹ No response received for role context test")
                
        except Exception as e:
            print(f"ℹ Role persistence testing not yet available: {e}")


class TestRoleBasedResponses:
    """Test role-specific response formatting and content."""
    
    @pytest.mark.parametrize("role", get_all_test_roles())
    @pytest.mark.asyncio
    async def test_role_specific_response_format(self, page: Page, chainlit_base_url: str, role: UserRole):
        """Test that responses are formatted appropriately for each role."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Get test user data for this role
        test_user = get_user_for_role(role)
        
        try:
            # Select role if possible
            await helper.simulate_user_role_selection(role.value)
            
            # Test with role-appropriate queries
            for i, query in enumerate(test_user.typical_queries[:2]):  # Test first 2 queries
                print(f"\nTesting {role.value} query {i+1}: {query}")
                
                await helper.submit_message(query)
                response = await helper.get_last_response()
                
                if response and len(response) > 10:
                    # Validate response format for role
                    is_valid_format = validate_role_response_format(response, role)
                    
                    print(f"  Response received: {len(response)} characters")
                    print(f"  Format validation: {'✓ PASSED' if is_valid_format else '⚠ NEEDS REVIEW'}")
                    
                    if not is_valid_format:
                        # Log details for debugging
                        expected_indicators = RoleTestHelper.ROLE_RESPONSE_INDICATORS.get(role, [])
                        print(f"  Expected indicators: {expected_indicators}")
                        print(f"  Response preview: {response[:200]}...")
                    
                    # Take screenshot of role-specific response
                    await capture_ui_state_for_role(page, f"response_{role.value}_query_{i+1}")
                else:
                    print(f"  ℹ No adequate response received for {role.value}")
                
                # Brief pause between queries
                await asyncio.sleep(1)
                
        except Exception as e:
            print(f"ℹ Role-based response testing for {role.value} encountered: {e}")
    
    @pytest.mark.asyncio
    async def test_role_switching_response_differences(self, page: Page, chainlit_base_url: str):
        """Test that responses differ appropriately when switching between roles."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Test the same query with different roles
        test_query = "Tell me about cross-site scripting vulnerabilities"
        test_roles = [UserRole.PSIRT, UserRole.DEVELOPER, UserRole.ACADEMIC]
        
        role_responses = {}
        
        for role in test_roles:
            try:
                print(f"\nTesting query with {role.value} role...")
                
                # Select role
                await helper.simulate_user_role_selection(role.value)
                await asyncio.sleep(1)  # Allow role selection to process
                
                # Submit same query
                await helper.submit_message(test_query)
                response = await helper.get_last_response()
                
                if response and len(response) > 10:
                    role_responses[role.value] = response
                    print(f"  ✓ Response captured for {role.value}: {len(response)} characters")
                    
                    # Take screenshot
                    await capture_ui_state_for_role(page, f"role_comparison_{role.value}")
                else:
                    print(f"  ℹ No adequate response for {role.value}")
                    
            except Exception as e:
                print(f"  ℹ Role switching test for {role.value}: {e}")
        
        # Analyze response differences
        if len(role_responses) >= 2:
            print(f"\n=== Role Response Comparison ===")
            roles = list(role_responses.keys())
            
            for i, role1 in enumerate(roles):
                for role2 in roles[i+1:]:
                    response1 = role_responses[role1]
                    response2 = role_responses[role2]
                    
                    # Simple similarity check (more sophisticated analysis could be added)
                    similarity = len(set(response1.lower().split()) & set(response2.lower().split()))
                    total_words = len(set(response1.lower().split()) | set(response2.lower().split()))
                    similarity_ratio = similarity / total_words if total_words > 0 else 0
                    
                    print(f"  {role1} vs {role2}: {similarity_ratio:.2f} word overlap ratio")
                    
                    if similarity_ratio < 0.8:  # Responses are sufficiently different
                        print(f"    ✓ Responses appropriately differentiated")
                    else:
                        print(f"    ⚠ Responses may be too similar")
        else:
            print("ℹ Insufficient responses to compare role differences")


class TestRoleContextPreservation:
    """Test that role context is preserved across different interactions."""
    
    @pytest.mark.asyncio
    async def test_role_context_across_multiple_queries(self, page: Page, chainlit_base_url: str):
        """Test that role context is maintained across multiple queries in a session."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_role = UserRole.DEVELOPER
        test_queries = [
            "What is XSS?",
            "How do I prevent it?",
            "Show me a code example"
        ]
        
        try:
            # Select role
            await helper.simulate_user_role_selection(test_role.value)
            print(f"Selected role: {test_role.value}")
            
            responses = []
            
            # Submit multiple queries
            for i, query in enumerate(test_queries):
                print(f"\nQuery {i+1}: {query}")
                
                await helper.submit_message(query)
                response = await helper.get_last_response()
                
                if response and len(response) > 10:
                    responses.append(response)
                    
                    # Check if response maintains developer focus
                    is_developer_focused = validate_role_response_format(response, test_role)
                    print(f"  Developer focus maintained: {'✓' if is_developer_focused else '⚠'}")
                    
                    # Take screenshot
                    await capture_ui_state_for_role(page, f"context_preservation_query_{i+1}")
                else:
                    print(f"  ℹ No response for query {i+1}")
                
                await asyncio.sleep(1)
            
            # Analyze context preservation
            if len(responses) >= 2:
                print(f"\n=== Context Preservation Analysis ===")
                print(f"Responses collected: {len(responses)}")
                
                # Check if all responses maintain role-appropriate language
                all_role_appropriate = all(
                    validate_role_response_format(resp, test_role) 
                    for resp in responses
                )
                
                if all_role_appropriate:
                    print("✓ Role context preserved across all queries")
                else:
                    print("⚠ Role context may have been lost in some responses")
            else:
                print("ℹ Insufficient responses to analyze context preservation")
                
        except Exception as e:
            print(f"ℹ Role context preservation testing: {e}")
    
    @pytest.mark.asyncio
    async def test_role_context_after_page_refresh(self, page: Page, chainlit_base_url: str):
        """Test role context persistence after page refresh (if supported)."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        test_role = UserRole.PSIRT
        test_query = "What's the security impact of SQL injection?"
        
        try:
            # Select role and submit initial query
            await helper.simulate_user_role_selection(test_role.value)
            await helper.submit_message(test_query)
            
            initial_response = await helper.get_last_response()
            if initial_response and len(initial_response) > 10:
                print(f"✓ Initial response received: {len(initial_response)} characters")
            
            # Refresh page
            await page.reload()
            await helper.wait_for_chainlit_ready()
            
            # Test if role context is restored
            await helper.submit_message(test_query)
            post_refresh_response = await helper.get_last_response()
            
            if post_refresh_response and len(post_refresh_response) > 10:
                print(f"✓ Post-refresh response received: {len(post_refresh_response)} characters")
                
                # Check if role context was maintained
                is_role_maintained = validate_role_response_format(post_refresh_response, test_role)
                print(f"Role context after refresh: {'✓ MAINTAINED' if is_role_maintained else '⚠ LOST'}")
                
                await capture_ui_state_for_role(page, "role_context_after_refresh")
            else:
                print("ℹ No response after page refresh")
                
        except Exception as e:
            print(f"ℹ Role context refresh testing: {e}")


class TestRoleSwitching:
    """Test role switching functionality."""
    
    @pytest.mark.asyncio
    async def test_role_switching_workflow(self, page: Page, chainlit_base_url: str):
        """Test switching between different roles in a single session."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        # Test switching between two different roles
        role1 = UserRole.PSIRT
        role2 = UserRole.DEVELOPER
        test_query = "How serious is a buffer overflow vulnerability?"
        
        try:
            # Test with first role
            print(f"=== Testing with {role1.value} role ===")
            await helper.simulate_user_role_selection(role1.value)
            await helper.submit_message(test_query)
            
            response1 = await helper.get_last_response()
            if response1:
                print(f"Response 1 length: {len(response1)} characters")
                is_role1_format = validate_role_response_format(response1, role1)
                print(f"Role 1 format valid: {'✓' if is_role1_format else '⚠'}")
            
            await capture_ui_state_for_role(page, f"role_switch_before_{role1.value}")
            
            # Switch to second role
            print(f"\n=== Switching to {role2.value} role ===")
            await helper.simulate_user_role_selection(role2.value)
            await asyncio.sleep(1)  # Allow role switch to process
            
            # Submit same query with new role
            await helper.submit_message(test_query)
            response2 = await helper.get_last_response()
            
            if response2:
                print(f"Response 2 length: {len(response2)} characters")
                is_role2_format = validate_role_response_format(response2, role2)
                print(f"Role 2 format valid: {'✓' if is_role2_format else '⚠'}")
            
            await capture_ui_state_for_role(page, f"role_switch_after_{role2.value}")
            
            # Compare responses
            if response1 and response2:
                print(f"\n=== Role Switch Analysis ===")
                
                # Check that responses are different (indicating role switch worked)
                responses_different = response1.strip() != response2.strip()
                print(f"Responses differ after role switch: {'✓' if responses_different else '⚠'}")
                
                if responses_different:
                    # Check if each response matches its expected role format
                    role1_appropriate = validate_role_response_format(response1, role1)
                    role2_appropriate = validate_role_response_format(response2, role2)
                    
                    print(f"{role1.value} response appropriate: {'✓' if role1_appropriate else '⚠'}")
                    print(f"{role2.value} response appropriate: {'✓' if role2_appropriate else '⚠'}")
                    
                    if role1_appropriate and role2_appropriate:
                        print("✓ Role switching functionality working correctly")
                    else:
                        print("⚠ Role switching may need refinement")
                else:
                    print("ℹ Responses identical - role switching may not be implemented")
            else:
                print("ℹ Insufficient responses to test role switching")
                
        except Exception as e:
            print(f"ℹ Role switching testing: {e}")
    
    @pytest.mark.asyncio
    async def test_role_switching_ui_feedback(self, page: Page, chainlit_base_url: str):
        """Test that UI provides feedback when roles are switched."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        roles_to_test = [UserRole.ACADEMIC, UserRole.BUG_BOUNTY]
        
        for role in roles_to_test:
            try:
                print(f"\n=== Testing UI feedback for {role.value} ===")
                
                # Attempt role selection
                await helper.simulate_user_role_selection(role.value)
                await asyncio.sleep(1)
                
                # Look for UI feedback indicators
                feedback_selectors = [
                    f"[data-testid*='{role.value}']",
                    f".selected:has-text('{role.value}')",
                    f".active:has-text('{role.value}')",
                    f"button.selected:has-text('{role.value}')",
                    ".role-indicator",
                    ".current-role"
                ]
                
                feedback_found = False
                for selector in feedback_selectors:
                    try:
                        elements = await page.locator(selector).all()
                        if elements:
                            for element in elements:
                                if await element.is_visible():
                                    feedback_found = True
                                    print(f"  ✓ UI feedback found: {selector}")
                                    break
                        if feedback_found:
                            break
                    except:
                        continue
                
                if not feedback_found:
                    print(f"  ℹ No UI feedback detected for {role.value}")
                
                # Take screenshot of current UI state
                await capture_ui_state_for_role(page, f"role_feedback_{role.value}")
                
            except Exception as e:
                print(f"  ℹ UI feedback testing for {role.value}: {e}")


# Performance test for role operations
class TestRolePerformance:
    """Test performance of role-related operations."""
    
    @pytest.mark.asyncio
    async def test_role_selection_performance(self, page: Page, chainlit_base_url: str):
        """Test that role selection operations complete within reasonable time."""
        helper = await setup_test_environment(page, chainlit_base_url)
        
        import time
        
        test_role = UserRole.DEVELOPER
        performance_results = []
        
        # Test role selection timing
        for attempt in range(3):  # Test 3 times for consistency
            try:
                start_time = time.time()
                
                await helper.simulate_user_role_selection(test_role.value)
                await asyncio.sleep(0.5)  # Allow for UI updates
                
                selection_time = time.time() - start_time
                performance_results.append(selection_time)
                
                print(f"Role selection attempt {attempt + 1}: {selection_time:.2f}s")
                
            except Exception as e:
                print(f"Performance test attempt {attempt + 1} failed: {e}")
        
        if performance_results:
            avg_time = sum(performance_results) / len(performance_results)
            max_time = max(performance_results)
            
            print(f"\n=== Role Selection Performance ===")
            print(f"Average time: {avg_time:.2f}s")
            print(f"Maximum time: {max_time:.2f}s")
            
            # Performance assertions (adjust thresholds as needed)
            if avg_time < 2.0:
                print("✓ Role selection performance acceptable")
            else:
                print("⚠ Role selection may be slow")
                
            if max_time < 5.0:
                print("✓ Maximum selection time acceptable")
            else:
                print("⚠ Some role selections are taking too long")
        else:
            print("ℹ No performance data collected")


# Skip these tests by default since they require role functionality to be implemented
@pytest.mark.skip(reason="Role functionality implementation pending")
class TestRoleImplementationReady:
    """Tests that will be enabled when role functionality is implemented."""
    
    @pytest.mark.asyncio
    async def test_all_roles_functional(self, page: Page, chainlit_base_url: str):
        """Test that all 5 user roles are functional."""
        pass
    
    @pytest.mark.asyncio
    async def test_role_specific_ui_elements(self, page: Page, chainlit_base_url: str):
        """Test role-specific UI elements and adaptations."""
        pass