#!/bin/sh
#bandit -r ./apps -x ./apps/chatbot/tests,./apps/cwe_ingestion/tests,./apps/pdf_worker/tests,./apps/tests -f json -o bandit_report_no_tests.json -iii -ll
#bandit -r ./apps -x ./apps/chatbot/tests,./apps/cwe_ingestion/tests,./apps/pdf_worker/tests,./apps/tests,./apps/cwe_ingestion/build/lib/tests -f json -o bandit_report_no_tests.json -iii -l
bandit -r ./apps -x ./apps/chatbot/tests,./apps/cwe_ingestion/tests,./apps/pdf_worker/tests,./apps/tests,./apps/cwe_ingestion/build/lib/tests,./apps/cwe_ingestion/scripts -f json -o bandit_report_no_tests.json -iii -l