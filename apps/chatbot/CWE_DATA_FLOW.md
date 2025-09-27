# CWE Data Flow

This document describes the flow of CWE data from the database to the final response presented to the user.

## 1. Overview

The chatbot uses a hybrid retrieval system to fetch relevant CWE data from a PostgreSQL database. This data is then used to construct a prompt for a Large Language Model (LLM), which generates a response in natural language. The LLM's response is then post-processed to ensure correctness and consistency.

## 2. Data Retrieval

When a user sends a message, the `CWEQueryHandler` in `src/query_handler.py` is responsible for retrieving relevant CWE data from the database. This is done using a hybrid retrieval approach that combines vector search, full-text search, and alias matching.

The `get_canonical_cwe_metadata` and `get_cwe_policy_labels` methods are used to retrieve the canonical name, abstraction level, status, and policy label for a given list of CWE IDs.

## 3. Prompt Engineering

Once the relevant CWE data has been retrieved, the `process_user_message_streaming` function in `src/conversation.py` constructs a prompt for the LLM. This prompt includes the following sections:

-   **[Canonical CWE Metadata]**: This section contains the canonical name, abstraction level, status, and mapping policy for the retrieved CWEs.
-   **[Policy Rules]**: This section provides the LLM with explicit instructions on how to use the mapping policy labels.

This is an important step to guide the LLM in generating a correct and consistent response.

## 4. Post-processing

After the LLM has generated a response, the `process_user_message_streaming` function in `src/conversation.py` performs a post-processing step to ensure the correctness and consistency of the generated table. This is done by the `harmonize_cwe_names_in_table` function in `src/utils/text_post.py`.

This function:
1.  Extracts all CWE IDs from the generated markdown table.
2.  Fetches the canonical names and policy labels for these CWE IDs from the database.
3.  Replaces the CWE names and policy labels in the table with the correct values from the database.

## 5. Limitations

A key challenge in this process is that the LLM may choose to include CWEs in its response that were not part of the initial retrieval. In such cases, the `[Canonical CWE Metadata]` block in the prompt will not contain the data for these new CWEs.

To address this, the post-processing step described above is crucial. By extracting all CWE IDs from the final generated table and fetching their data from the database, we can ensure that the table is always correct and consistent, regardless of which CWEs the LLM chooses to include.
