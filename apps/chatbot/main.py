#!/usr/bin/env python3
"""
CWE ChatBot - Basic Chainlit Application
A minimal Chainlit application for deployment to Google Cloud Run.
"""

import chainlit as cl


@cl.on_chat_start
async def start():
    """Initialize the chat session with a welcome message."""
    await cl.Message(
        content="Hello, welcome to CWE ChatBot! 👋\n\nI'm a basic deployment test. How can I help you today?"
    ).send()


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages from users."""
    user_content = message.content.strip()
    
    # Simple echo response for basic functionality testing
    response = f"Thanks for your message: '{user_content}'\n\nThis is a basic deployment test of the CWE ChatBot infrastructure."
    
    await cl.Message(content=response).send()


if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    import os
    import sys
    
    # Add current directory to path for imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Run with chainlit
    os.system("chainlit run main.py")