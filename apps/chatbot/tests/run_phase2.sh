#!/bin/bash
# Run Phase 2 LLM-as-Judge tests

export CHATBOT_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"

# Get secrets from Secret Manager
export TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key --project=cwechatbot)
export GEMINI_API_KEY=$(gcloud secrets versions access latest --secret=gemini-api-key --project=cwechatbot)

cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad/apps/chatbot/tests

echo "Running Phase 2: LLM-as-Judge Tests"
echo "===================================="
echo "CHATBOT_URL: $CHATBOT_URL"
echo ""

poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py -v --tb=line
