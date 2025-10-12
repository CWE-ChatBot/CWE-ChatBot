#!/bin/bash
export CHATBOT_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
export TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key --project=cwechatbot)
export GEMINI_API_KEY=$(gcloud secrets versions access latest --secret=gemini-api-key --project=cwechatbot)

poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py -k "CWE-79 or CWE-82 or CWE-89" -s --tb=line
