#!/usr/bin/env python3
"""
CWE ChatBot - Hybrid RAG Application
Advanced Chainlit application with NLU, security sanitization, and hybrid retrieval.
"""

import asyncio
import logging
import sys
import os
import subprocess
from pathlib import Path

import chainlit as cl

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import config
from src.retrieval.hybrid_rag_manager import HybridRAGManager
from src.processing.query_processor import QueryProcessor
from src.processing.embedding_service import EmbeddingService
from src.formatting.response_formatter import ResponseFormatter
# Story 2.2: Session management imports
from src.session.context_manager import SessionContextManager
from src.session.session_security import SessionSecurityValidator
# Story 2.2: Progressive disclosure imports
from src.formatting.progressive_response_formatter import ProgressiveResponseFormatter
from src.processing.contextual_responder import ContextualResponder
# Story 2.3: Role-based context imports
from src.user.role_manager import RoleManager, UserRole
from src.processing.role_aware_responder import RoleAwareResponder
# Security imports - Rate limiting and secure logging
from src.security.rate_limiting import action_button_rate_limit, query_rate_limit, RateLimitExceeded
from src.security.secure_logging import get_secure_logger


# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = get_secure_logger(__name__)

# Global components (initialized on startup)
query_processor = None
hybrid_rag_manager = None
response_formatter = None
# Story 2.2: Session management components
session_manager = None
session_security = None
# Story 2.2: Progressive disclosure components
progressive_formatter = None
contextual_responder = None
# Story 2.3: Role management components
role_manager = None
role_aware_responder = None


def initialize_components():
    """Initialize all chatbot components with error handling."""
    global query_processor, hybrid_rag_manager, response_formatter, session_manager, session_security, progressive_formatter, contextual_responder, role_manager, role_aware_responder
    
    try:
        # Validate configuration
        config.validate_config()
        logger.info("Configuration validated successfully")
        
        # Initialize query processor with security settings
        query_processor = QueryProcessor(
            max_input_length=config.max_input_length,
            strict_mode=config.enable_strict_sanitization
        )
        
        # Initialize embedding service
        embedding_service = EmbeddingService(
            api_key=config.openai_api_key,
            model=config.embedding_model,
            dimensions=config.embedding_dimensions
        )
        
        # Initialize hybrid RAG manager
        hybrid_rag_manager = HybridRAGManager(
            pg_config=config.get_pg_config(),
            embedding_service=embedding_service,
            weights=config.get_hybrid_weights()
        )
        
        # Initialize response formatter
        response_formatter = ResponseFormatter(
            max_results_display=config.max_retrieval_results,
            show_confidence_scores=True,
            show_source_methods=config.enable_debug_logging
        )
        
        # Story 2.2: Initialize session management components
        session_manager = SessionContextManager()
        session_security = SessionSecurityValidator()
        
        # Story 2.2: Initialize progressive disclosure components
        progressive_formatter = ProgressiveResponseFormatter()
        contextual_responder = ContextualResponder()
        
        # Story 2.3: Initialize role management components
        role_manager = RoleManager()
        role_aware_responder = RoleAwareResponder(mock_llm=True)  # Use mock for now
        
        logger.info("All components initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Component initialization failed: {e}")
        return False


@cl.on_chat_start
async def start():
    """Initialize the chat session with role selection."""
    global role_manager
    
    # Check if role is already selected (returning user)
    if role_manager and role_manager.is_role_selected():
        current_role = role_manager.get_current_role()
        welcome_message = f"""Hello! Welcome back to the CWE ChatBot! 🛡️

Your current role: **{current_role.get_display_name() if current_role else 'Unknown'}**

I'm here to help you with Common Weakness Enumeration (CWE) information. You can:

• Ask about specific CWEs (e.g., "Tell me about CWE-79")
• Search for vulnerabilities by type (e.g., "SQL injection vulnerabilities") 
• Get prevention guidance (e.g., "How to prevent buffer overflows")
• Learn about security concepts and best practices

What would you like to know about cybersecurity weaknesses?

*To change your role, use the "Change Role" button below.*"""
        
        actions = [cl.Action(name="change_role", value="change_role", label="Change Role")]
        await cl.Message(content=welcome_message, actions=actions).send()
    else:
        # New session - prompt for role selection
        welcome_message = """Hello! Welcome to the CWE ChatBot! 🛡️

To provide you with the most relevant information, please select your role:"""
        
        if role_manager:
            role_actions = role_manager.get_role_actions()
            await cl.Message(content=welcome_message, actions=role_actions).send()
        else:
            # Fallback if role manager not initialized
            await cl.Message(content="System is initializing. Please try again in a moment.").send()


@cl.on_message
@query_rate_limit(max_requests=30, window=60)  # 30 queries per minute
async def main(message: cl.Message):
    """Handle incoming messages with full NLU and retrieval pipeline."""
    
    # Check if components are initialized
    if not all([query_processor, hybrid_rag_manager, response_formatter, session_manager, session_security, progressive_formatter, contextual_responder, role_manager, role_aware_responder]):
        error_msg = response_formatter.get_fallback_response("system_error") if response_formatter else "System is initializing. Please try again in a moment."
        await cl.Message(content=error_msg).send()
        return
    
    # Story 2.3: Check if user needs to select role first
    if not role_manager.is_role_selected():
        await cl.Message(content="Please select your role first using the buttons above before asking questions.").send()
        return
    
    # Story 2.2: Session security validation
    session_id = session_manager._get_session_id()
    if session_id and not session_security.validate_session_isolation(session_id):
        logger.error(f"Session isolation validation failed for {session_id}")
        error_msg = response_formatter.get_fallback_response("system_error")
        await cl.Message(content=error_msg).send()
        return
    
    try:
        user_query = message.content.strip()
        logger.info(f"Processing user query of length {len(user_query)}")
        
        # Get session ID for rate limiting
        session_id = session_manager._get_session_id()
        
        # Story 2.2: Get current session context
        current_context = session_manager.get_current_cwe()
        session_context = {'current_cwe': current_context} if current_context else None
        
        # Step 1: Context-aware query preprocessing with security validation
        try:
            processed_query = query_processor.process_with_context(user_query, session_context)
            logger.debug(f"Query type: {processed_query.get('query_type', 'unknown')}")
        except (ValueError, TypeError) as e:
            # Security validation failed
            logger.warning(f"Query rejected by security validation: {e}")
            error_response = response_formatter.get_fallback_response("invalid_query")
            await cl.Message(content=error_response).send()
            return
        
        # Step 2: Determine retrieval approach based on context
        if processed_query.get('is_followup', False):
            # Follow-up query processing
            context_cwe = processed_query.get('context_cwe')
            intent = processed_query.get('followup_intent')
            
            # Get comprehensive data for the context CWE
            comprehensive_result = hybrid_rag_manager.get_comprehensive_cwe(context_cwe)
            
            # Handle different follow-up intents
            if intent.intent_type == 'related':
                results = hybrid_rag_manager.find_similar_cwes(context_cwe, k=5)
            elif intent.intent_type in ['children', 'parents']:
                relationship_type = 'ChildOf' if intent.intent_type == 'parents' else 'ParentOf'
                results = hybrid_rag_manager.get_related_cwes(context_cwe, relationship_type)
            else:
                # For other intents, use the comprehensive result
                results = [comprehensive_result] if comprehensive_result else []
            
            # Generate contextual response
            if comprehensive_result:
                relationship_data = {
                    'relationships': comprehensive_result.relationships,
                    'consequences': comprehensive_result.consequences,
                    'extended_description': comprehensive_result.extended_description
                }
                
                contextual_response = contextual_responder.generate_contextual_response(
                    user_query, context_cwe, intent, relationship_data, results
                )
                
                # Format and send contextual response
                content, actions = progressive_formatter.format_contextual_summary(
                    contextual_response, comprehensive_result
                )
                
                await cl.Message(content=content, actions=actions).send()
                logger.info(f"Successfully processed follow-up query: {intent.intent_type}")
            else:
                # Fallback if context CWE not found
                error_response = f"I couldn't find information about {context_cwe}. Let me search for your query instead."
                await cl.Message(content=error_response).send()
                # Fall through to regular processing
                processed_query['is_followup'] = False
        
        if not processed_query.get('is_followup', False):
            # Regular query processing
            search_strategy = processed_query.get('search_strategy', 'hybrid_search')
            
            # Perform retrieval with relationships
            if search_strategy == "direct_lookup":
                results = hybrid_rag_manager.search_with_relationships(
                    processed_query['sanitized_query'],
                    k=config.max_retrieval_results,
                    include_relationships=True,
                    strategy="direct",
                    cwe_ids=processed_query.get('cwe_ids', [])
                )
            else:
                search_method = "hybrid" if search_strategy == "hybrid_search" else search_strategy.replace("_search", "")
                results = hybrid_rag_manager.search_with_relationships(
                    processed_query['sanitized_query'],
                    k=config.max_retrieval_results,
                    include_relationships=True,
                    strategy=search_method,
                    keyphrases=processed_query.get('keyphrases', {}),
                    boost_factors=processed_query.get('boost_factors', {})
                )
            
            # Story 2.2 & 2.3: Use role-aware progressive disclosure for responses
            if results:
                primary_result = results[0]
                
                # Update session context with the primary result
                session_manager.set_current_cwe(
                    primary_result.cwe_id,
                    {
                        'name': primary_result.name,
                        'description': primary_result.description,
                        'confidence': primary_result.confidence_score
                    }
                )
                
                # Story 2.3: Get user's role for tailored response
                current_role = role_manager.get_current_role()
                
                # Generate role-aware response
                role_response = await role_aware_responder.generate_role_based_response(
                    query=user_query,
                    role=current_role,
                    cwe_results=results,
                    confidence_score=primary_result.confidence_score
                )
                
                # Combine role-aware content with progressive disclosure and enhanced confidence
                if processed_query.get('query_type') == 'direct_cwe_lookup' and len(results) == 1:
                    # Single CWE lookup - show role-tailored summary with actions
                    content, actions = progressive_formatter.format_summary_response(primary_result)
                    
                    # Build enhanced response with confidence scoring
                    role_context = role_aware_responder.get_role_context_summary(current_role)
                    enhanced_content = f"*{role_context}*\n\n{role_response.content}\n\n"
                    
                    # Add enhanced confidence display
                    if role_response.confidence_display:
                        enhanced_content += f"{role_response.confidence_display}\n\n"
                    
                    # Add low confidence warning if present
                    if role_response.low_confidence_warning:
                        enhanced_content += f"{role_response.low_confidence_warning}\n\n"
                    
                    enhanced_content += f"---\n\n{content}"
                    await cl.Message(content=enhanced_content, actions=actions).send()
                else:
                    # Multiple results - show role-aware summary of top result plus list
                    content, actions = progressive_formatter.format_summary_response(primary_result)
                    
                    # Build role-specific response with enhanced confidence
                    role_context = role_aware_responder.get_role_context_summary(current_role)
                    role_intro = f"*{role_context}*\n\n{role_response.content}\n\n"
                    
                    # Add enhanced confidence display
                    if role_response.confidence_display:
                        role_intro += f"{role_response.confidence_display}\n\n"
                    
                    # Add low confidence warning if present  
                    if role_response.low_confidence_warning:
                        role_intro += f"{role_response.low_confidence_warning}\n\n"
                    
                    if len(results) > 1:
                        additional_results = "\n\n**Other relevant CWEs:**\n"
                        for result in results[1:4]:  # Show up to 3 additional
                            additional_results += f"• **{result.cwe_id}**: {result.name}\n"
                        content += additional_results
                    
                    final_content = role_intro + "---\n\n" + content
                    await cl.Message(content=final_content, actions=actions).send()
                
                logger.info(f"Successfully processed query with role-aware response for {current_role.value if current_role else 'no role'}, returned {len(results)} results")
            else:
                # No results found
                error_response = response_formatter.get_fallback_response("no_results")
                await cl.Message(content=error_response).send()
        
    except RateLimitExceeded as e:
        # Handle rate limit exceeded
        logger.warning(f"Rate limit exceeded for query processing: {e}")
        retry_msg = f"You're sending messages too quickly. Please wait {e.retry_after} seconds before trying again."
        await cl.Message(content=retry_msg).send()
    except Exception as e:
        # Secure error handling - never expose internal details
        logger.log_exception("Error processing query", e, extra_context={
            'component': 'main_message_handler',
            'query_length': len(user_query) if 'user_query' in locals() else 0
        })
        error_response = response_formatter.get_fallback_response("system_error")
        await cl.Message(content=error_response).send()


# Story 2.2: Action handlers for progressive disclosure

@cl.action_callback("tell_more")
@action_button_rate_limit(max_requests=10, window=60)  # 10 clicks per minute
async def on_tell_more(action):
    """Handle 'tell me more' action button clicks."""
    try:
        if not progressive_formatter or not hybrid_rag_manager:
            await cl.Message(content="System components not available.").send()
            return
        
        # Get session ID and parse action value with CSRF validation
        session_id = session_manager._get_session_id() if session_manager else None
        action_meta = progressive_formatter.get_action_metadata(action.value, session_id)
        
        # Validate CSRF token if enabled
        if not action_meta.get('csrf_valid', True):  # True if CSRF disabled
            await cl.Message(content="Security validation failed. Please refresh and try again.").send()
            logger.warning(f"CSRF validation failed for tell_more action: {action_meta.get('csrf_reason')}")
            return
        
        cwe_id = action_meta.get('cwe_id')
        
        if not cwe_id:
            await cl.Message(content="Unable to retrieve detailed information.").send()
            return
        
        # Get comprehensive CWE data
        comprehensive_result = hybrid_rag_manager.get_comprehensive_cwe(cwe_id)
        if comprehensive_result:
            detailed_response = progressive_formatter.format_detailed_response(
                comprehensive_result, "comprehensive"
            )
            await cl.Message(content=detailed_response).send()
            logger.info(f"Provided detailed information for {cwe_id}")
        else:
            await cl.Message(content=f"Detailed information for {cwe_id} is not available.").send()
            
    except RateLimitExceeded as e:
        logger.warning(f"Rate limit exceeded for tell_more action: {e}")
        await cl.Message(content=f"Too many requests. Please wait {e.retry_after} seconds.").send()
    except Exception as e:
        logger.log_exception("Tell more action failed", e, extra_context={'action': 'tell_more'})
        await cl.Message(content="Sorry, I encountered an error retrieving detailed information.").send()


@cl.action_callback("show_consequences") 
async def on_show_consequences(action):
    """Handle 'show consequences' action button clicks."""
    try:
        if not progressive_formatter or not hybrid_rag_manager:
            await cl.Message(content="System components not available.").send()
            return
        
        action_meta = progressive_formatter.get_action_metadata(action.value)
        cwe_id = action_meta.get('cwe_id')
        
        if not cwe_id:
            await cl.Message(content="Unable to retrieve consequence information.").send()
            return
        
        comprehensive_result = hybrid_rag_manager.get_comprehensive_cwe(cwe_id)
        if comprehensive_result:
            consequences_response = progressive_formatter.format_detailed_response(
                comprehensive_result, "consequences"
            )
            await cl.Message(content=consequences_response).send()
            logger.info(f"Provided consequences information for {cwe_id}")
        else:
            await cl.Message(content=f"Consequences information for {cwe_id} is not available.").send()
            
    except Exception as e:
        logger.log_exception("Show consequences action failed", e, extra_context={'action': 'show_consequences'})
        await cl.Message(content="Sorry, I encountered an error retrieving consequences information.").send()


@cl.action_callback("show_related")
async def on_show_related(action):
    """Handle 'show related' action button clicks."""
    try:
        if not progressive_formatter or not hybrid_rag_manager:
            await cl.Message(content="System components not available.").send()
            return
        
        action_meta = progressive_formatter.get_action_metadata(action.value)
        cwe_id = action_meta.get('cwe_id')
        
        if not cwe_id:
            await cl.Message(content="Unable to retrieve related CWE information.").send()
            return
        
        # Get similar CWEs
        similar_cwes = hybrid_rag_manager.find_similar_cwes(cwe_id, k=5)
        
        if similar_cwes:
            related_response = f"**CWEs related to {cwe_id}:**\n\n"
            for cwe in similar_cwes:
                confidence_pct = int(cwe.confidence_score * 100) 
                related_response += f"**{cwe.cwe_id}**: {cwe.name}\n"
                related_response += f"*Similarity: {confidence_pct}%*\n\n"
            
            await cl.Message(content=related_response).send()
            logger.info(f"Provided related CWEs for {cwe_id}")
        else:
            await cl.Message(content=f"No closely related CWEs found for {cwe_id}.").send()
            
    except Exception as e:
        logger.log_exception("Show related action failed", e, extra_context={'action': 'show_related'})
        await cl.Message(content="Sorry, I encountered an error retrieving related information.").send()


@cl.action_callback("show_prevention")
async def on_show_prevention(action):
    """Handle 'show prevention' action button clicks."""
    try:
        if not progressive_formatter or not hybrid_rag_manager:
            await cl.Message(content="System components not available.").send()
            return
        
        action_meta = progressive_formatter.get_action_metadata(action.value)
        cwe_id = action_meta.get('cwe_id')
        
        if not cwe_id:
            await cl.Message(content="Unable to retrieve prevention information.").send()
            return
        
        comprehensive_result = hybrid_rag_manager.get_comprehensive_cwe(cwe_id)
        if comprehensive_result:
            prevention_response = progressive_formatter.format_detailed_response(
                comprehensive_result, "prevention"
            )
            await cl.Message(content=prevention_response).send()
            logger.info(f"Provided prevention information for {cwe_id}")
        else:
            await cl.Message(content=f"Prevention information for {cwe_id} is not available.").send()
            
    except Exception as e:
        logger.log_exception("Show prevention action failed", e, extra_context={'action': 'show_prevention'})
        await cl.Message(content="Sorry, I encountered an error retrieving prevention information.").send()


# Story 2.3: Role selection action callbacks

@cl.action_callback("select_role_psirt")
async def on_select_psirt_role(action):
    """Handle PSIRT role selection."""
    await handle_role_selection(UserRole.PSIRT)

@cl.action_callback("select_role_developer")
async def on_select_developer_role(action):
    """Handle Developer role selection."""
    await handle_role_selection(UserRole.DEVELOPER)

@cl.action_callback("select_role_academic")
async def on_select_academic_role(action):
    """Handle Academic role selection."""
    await handle_role_selection(UserRole.ACADEMIC)

@cl.action_callback("select_role_bug_bounty")
async def on_select_bug_bounty_role(action):
    """Handle Bug Bounty Hunter role selection."""
    await handle_role_selection(UserRole.BUG_BOUNTY)

@cl.action_callback("select_role_product_manager")
async def on_select_product_manager_role(action):
    """Handle Product Manager role selection."""
    await handle_role_selection(UserRole.PRODUCT_MANAGER)

@cl.action_callback("change_role")
async def on_change_role(action):
    """Handle role change request."""
    global role_manager
    
    if not role_manager:
        await cl.Message(content="Role management not available.").send()
        return
    
    # Clear current role
    role_manager.clear_role()
    
    # Show role selection options
    welcome_message = "Please select your new role:"
    role_actions = role_manager.get_role_actions()
    await cl.Message(content=welcome_message, actions=role_actions).send()


async def handle_role_selection(role: UserRole):
    """Handle role selection logic."""
    global role_manager
    
    if not role_manager:
        await cl.Message(content="Role management not available.").send()
        return
    
    try:
        # Validate role integrity before setting
        if not role_manager.validate_role_integrity():
            logger.warning("Role integrity validation failed during selection")
            role_manager.clear_role()  # Clear potentially compromised data
        
        # Set the role
        success = role_manager.set_user_role(role)
        
        if success:
            confirmation_message = f"""Great! Your role has been set to **{role.get_display_name()}**.

{role.get_description()}

I'm ready to help you with CWE information tailored to your needs. What would you like to know about cybersecurity weaknesses?"""
            
            await cl.Message(content=confirmation_message).send()
            logger.info(f"Role successfully set to {role.get_display_name()}")
        else:
            await cl.Message(content="Sorry, there was an error setting your role. Please try again.").send()
            logger.error(f"Failed to set role to {role.get_display_name()}")
            
    except Exception as e:
        logger.log_exception("Role selection failed", e, extra_context={'role': role.value})
        await cl.Message(content="Sorry, there was an error with role selection. Please try again.").send()


def main_cli():
    """CLI entry point for running the application."""
    # Initialize components on startup
    if not initialize_components():
        logger.error("Failed to initialize components. Exiting.")
        sys.exit(1)
    
    logger.info("CWE ChatBot is ready to serve requests")


if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()
    
    # SECURITY FIX: Replace os.system() with secure subprocess.run()
    # This prevents shell command injection vulnerabilities
    try:
        subprocess.run([
            "python", "-m", "chainlit", "run", "main.py",
            "--host", "0.0.0.0", "--port", "8080"
        ], check=True, cwd=Path(__file__).parent)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start Chainlit server: {e}")
        sys.exit(1)
    except FileNotFoundError:
        logger.error("Chainlit not found. Please install with: pip install chainlit")
        sys.exit(1)