#!/usr/bin/env python3
"""
CWE ChatBot - Simple Demo Version
Basic Chainlit application with Gemini AI integration.
"""

import chainlit as cl
import logging
import os
from typing import Optional
from google.cloud import aiplatform
import vertexai
from vertexai.generative_models import GenerativeModel

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Vertex AI with service account authentication
try:
    # Get project ID from environment or use current project
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "cwechatbot")
    location = os.getenv("VERTEX_AI_LOCATION", "us-central1")

    # Initialize Vertex AI
    vertexai.init(project=project_id, location=location)

    # Initialize Gemini model
    model = GenerativeModel("gemini-2.5-flash-lite")
    logger.info(f"Vertex AI Gemini configured successfully for project {project_id}")
    ai_available = True
except Exception as e:
    model = None
    ai_available = False
    logger.error(f"Failed to initialize Vertex AI: {e}")

async def get_gemini_response(query: str) -> str:
    """Get response from Vertex AI Gemini with CWE context."""
    if not model or not ai_available:
        return "🔧 AI service not available. Vertex AI authentication may need to be configured."

    try:
        # Create a prompt that emphasizes CWE and cybersecurity context
        prompt = f"""You are a cybersecurity expert specializing in Common Weakness Enumeration (CWE).
        Please respond to the following question with accurate cybersecurity information.
        If the question is about CWEs, provide detailed technical information.
        If it's a general question, relate it to cybersecurity when possible.
        Keep responses concise but informative.

        Question: {query}

        Response:"""

        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Vertex AI Gemini error: {e}")
        return f"🤖 I encountered an error processing your request. Error: {str(e)}"

@cl.on_chat_start
async def start():
    """Initialize the chat session with title, subtitle and action buttons."""
    if model and ai_available:
        welcome_msg = """# CWE ChatBot

*Your AI-powered assistant for understanding the Common Weakness Enumeration*

Choose a question below or ask me anything about CWEs and cybersecurity vulnerabilities."""

        # Create action buttons for pre-made questions
        actions = [
            cl.Action(name="explain_cwe79", value="explain_cwe79", label="Explain CWE-79", payload={"action": "explain_cwe79"}),
            cl.Action(name="prevent_sql_injection", value="prevent_sql_injection", label="How do I prevent SQL injection?", payload={"action": "prevent_sql_injection"}),
            cl.Action(name="compare_cwe89_566", value="compare_cwe89_566", label="Compare CWE-89 and CWE-566", payload={"action": "compare_cwe89_566"})
        ]

        await cl.Message(content=welcome_msg, actions=actions).send()
    else:
        welcome_msg = """# CWE ChatBot

*Your AI-powered assistant for understanding the Common Weakness Enumeration*

⚠️ AI service unavailable - Vertex AI authentication not configured.

Please ask the administrator to set up Vertex AI permissions."""

        await cl.Message(content=welcome_msg).send()

@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Gemini AI responses."""
    user_query = message.content.strip()

    # Show typing indicator
    async with cl.Step(name="thinking", type="tool") as step:
        step.output = "Generating response..."

        # Get AI response
        if model and ai_available:
            response = await get_gemini_response(user_query)
        else:
            # Fallback responses when Vertex AI not available
            if "cwe" in user_query.lower():
                response = "🔍 CWE (Common Weakness Enumeration) is a community-developed list of software and hardware weakness types. For detailed information, I'd need Vertex AI permissions configured."
            elif "hello" in user_query.lower() or "hi" in user_query.lower():
                response = "Hello! 👋 I'm the CWE ChatBot demo. I'd be much more helpful with AI capabilities if Vertex AI was properly configured!"
            elif "help" in user_query.lower():
                response = "🛠️ I can help with cybersecurity questions when Vertex AI is configured. Please ask admin to set up Vertex AI permissions."
            else:
                response = f"Thanks for your message: '{message.content}'\n\n⚠️ AI service unavailable - please configure Vertex AI permissions."

    await cl.Message(content=response).send()


# Action callbacks for pre-made question buttons
@cl.action_callback("explain_cwe79")
async def on_explain_cwe79(action):
    """Handle CWE-79 explanation request."""
    query = "Explain CWE-79 (Cross-site Scripting)"
    response = await get_gemini_response(query)
    await cl.Message(content=response).send()


@cl.action_callback("prevent_sql_injection")
async def on_prevent_sql_injection(action):
    """Handle SQL injection prevention request."""
    query = "How do I prevent SQL injection attacks? What are the best practices?"
    response = await get_gemini_response(query)
    await cl.Message(content=response).send()


@cl.action_callback("compare_cwe89_566")
async def on_compare_cwe89_566(action):
    """Handle CWE comparison request."""
    query = "Compare CWE-89 (SQL Injection) and CWE-566 (Authorization Bypass). What are the key differences?"
    response = await get_gemini_response(query)
    await cl.Message(content=response).send()


if __name__ == "__main__":
    logger.info("CWE ChatBot Demo is ready to serve requests")