#!/usr/bin/env python3
"""
Quick test to verify OpenAI API integration works with the loaded environment.
This tests the ACTUAL OpenAI API integration following CLAUDE.md principles.
"""

import os
import sys
from pathlib import Path

# Load environment using configurable approach
try:
    # Add src to path and import environment loader
    sys.path.insert(0, str(Path(__file__).parent / "apps" / "chatbot" / "src"))
    from config.env_loader import get_env_info, load_env_auto

    success = load_env_auto()
    if success:
        env_info = get_env_info()
        print(f"✅ Environment loaded from: {env_info.get('loaded_from')}")
    else:
        print("❌ No environment file found")
        sys.exit(1)
except ImportError as e:
    print(f"❌ Could not import environment loader: {e}")
    print("💡 Falling back to manual environment check")
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY not found in environment")
        sys.exit(1)

# Test OpenAI API
try:
    import openai

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY not found in environment")
        sys.exit(1)

    print(f"🔑 API Key loaded: {api_key[:10]}...")

    # Initialize OpenAI client
    client = openai.Client(api_key=api_key)

    # Test actual embedding API call
    print("🚀 Testing real OpenAI text-embedding-3-small API...")
    test_query = "Cross-site scripting vulnerability"

    response = client.embeddings.create(
        input=test_query, model="text-embedding-3-small"
    )

    embedding = response.data[0].embedding

    # Verify real response
    print("✅ Real API call successful!")
    print(f"📊 Embedding dimensions: {len(embedding)}")
    print(f"📊 First 5 values: {embedding[:5]}")
    print(f"📊 Sum of absolute values: {sum(abs(x) for x in embedding):.2f}")

    # Test batch embeddings
    print("\n🚀 Testing batch embeddings...")
    batch_queries = [
        "SQL injection attack",
        "Buffer overflow vulnerability",
        "Input validation security",
    ]

    batch_response = client.embeddings.create(
        input=batch_queries, model="text-embedding-3-small"
    )

    print("✅ Batch API call successful!")
    print(f"📊 Batch size: {len(batch_response.data)}")
    for i, data in enumerate(batch_response.data):
        print(f"📊 Query {i+1} embedding dimension: {len(data.embedding)}")

    print("\n🎉 All OpenAI API tests passed! Real integration working.")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Run: poetry add openai")
    sys.exit(1)
except Exception as e:
    print(f"❌ OpenAI API error: {e}")
    sys.exit(1)
