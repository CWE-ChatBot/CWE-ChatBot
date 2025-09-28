Based on your additional context, a more robust configuration plan is needed to handle different environments (local dev, testing, GCP) securely.

Here is a detailed, step-by-step plan for your developer to create a clean, flexible, and production-ready configuration system.

Objective
The goal is to create a single, authoritative configuration module at src/config.py. This module will:

Load secrets from specific, non-repository .env files for local development and testing.

Prioritize real environment variables over those in .env files, making it ready for GCP deployment where secrets are injected into the environment.

Provide a simple, consistent config object for the rest of the application to use.

Phase 1: Enhance the Environment Loader ⚙️
The current env_loader.py is custom. We'll replace it with a more standard and powerful approach using the python-dotenv library, which is the industry standard.

Step 1.1: Add Dependency
First, ensure python-dotenv is in your project's dependency file.

File: requirements.txt

# requirements.txt
...
python-dotenv
...
Step 1.2: Refactor src/config/env_loader.py
Replace the entire content of src/config/env_loader.py with the following code. This new version uses an environment variable ENV_CONTEXT to decide which .env file to load.

File: src/config/env_loader.py

Python

"""
Environment loader that selects a .env file based on the ENV_CONTEXT 
environment variable. It prioritizes existing environment variables
over values in .env files, making it suitable for both local dev and
cloud deployments (e.g., GCP).
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

def load_environments():
    """
    Loads environment variables from a context-specific .env file.

    The file to load is determined by the `ENV_CONTEXT` environment variable.
    - 'development': Loads '~/work/env/.env_cwe_chatbot'
    - 'test': Loads './.env.test.local'
    - Unset/Other: Does not load any .env file (for production/GCP).

    IMPORTANT: This will NOT override any environment variables that are
    already set. This is the key to making it work seamlessly in GCP.
    """
    context = os.getenv("ENV_CONTEXT", "production").lower()
    path_map = {
        "development": Path.home() / "work" / "env" / ".env_cwe_chatbot",
        "test": Path(".env.test.local")
    }

    if context not in path_map:
        logger.info(
            f"ENV_CONTEXT is '{context}'. No .env file will be loaded. "
            "Assuming production environment."
        )
        return

    path = path_map[context].resolve()

    if not path.exists():
        logger.warning(
            f"ENV_CONTEXT is '{context}', but the expected file was not found at: {path}"
        )
        return

    # load_dotenv will find the file and load it into the environment.
    # `override=False` is the default and the desired behavior.
    # If a variable is already set (e.g., by GCP), it WON'T be overwritten.
    load_dotenv(dotenv_path=path)
    logger.info(f"✅ Loaded environment variables from: {path}")

Phase 2: Create the Authoritative src/config.py 🏛️
This step consolidates your configuration classes into a single, clean file.

Step 2.1: Rename the File
Rename the file src/app_config_extended.py to src/config.py.

Step 2.2: Update the Top of the New src/config.py
Modify the beginning of the newly renamed src/config.py to use the new loader function.

File: src/config.py

Current Code (at the top):

Python

"""
Configuration management for CWE ChatBot application.
Handles environment variables and application settings.
"""
import os
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config.env_loader import load_env_auto

# Auto-load environment on import
load_env_auto()

@dataclass
class Config:
    # ... rest of the file
New Code (replace the above block with this):

Python

"""
Authoritative configuration module for the CWE ChatBot application.
It loads the environment and then defines the Config object.
"""
import os
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config.env_loader import load_environments

# Load context-specific environment variables from .env files if available.
# This function must be called BEFORE the Config class is defined.
load_environments()

@dataclass
class Config:
    # --- NO CHANGES ARE NEEDED BELOW THIS LINE ---
    # The rest of the file correctly uses os.getenv(), which now reads
    # from the full environment (OS + .env file).
    
    # PostgreSQL Database Configuration
    pg_host: str = os.getenv("POSTGRES_HOST", "localhost")
    # ... rest of the file
Phase 3: Clean Up and Update Imports ♻️
The final step is to remove the old files and make sure the rest of the application points to the new src/config.py.

Step 3.1: Delete Redundant Files
Delete the following unnecessary file:

src/app_config.py

Step 3.2: Project-Wide Find and Replace
Perform a search across your entire project for the following import statements:

from src.app_config import config

from src.app_config_extended import config

Replace all occurrences with the new, authoritative import:

from src.config import config

Files that will likely need this change include:

src/conversation.py

src/query_handler.py

src/llm_provider.py

src/response_generator.py

Summary of the New Workflow
This new system provides a clear and robust way to manage configuration:

For Local Development: Before running the app, set the context in your terminal:

Bash

export ENV_CONTEXT=development
python -m chainlit run ... 
The app will start and automatically load secrets from ~/work/env/.env_cwe_chatbot.

For Playwright Testing: Your test runner should set the context:

Bash

export ENV_CONTEXT=test
playwright test
The tests will load configuration from .env.test.local.

For GCP Deployment: Do nothing. Do not set ENV_CONTEXT. The app will skip loading any .env files and will only use the environment variables provided by the GCP runtime (e.g., from Secret Manager or Cloud Run settings). This is exactly what you want for a secure production environment.








Playwright Testing can be part of local development



Show thinking
You're right. Playwright testing is a key part of the local development workflow. My apologies for presenting them as completely separate contexts.

The plan can easily be adapted for two common scenarios: keeping your test environment isolated (recommended best practice) or merging them for simplicity.

Here’s an updated, more flexible plan that lets you choose.

The Goal: A Robust and Clear Local Setup
The core idea remains the same: use an ENV_CONTEXT variable to load the correct .env file. The key is deciding if your automated tests should share the exact same configuration (especially the database) as your manual development.


Unified Local Environment (Simpler Approach) ⚙️
If your tests can safely run against your main development database, you can simplify the setup to use a single local environment.

Implementation Plan:
This requires a small change to the proposed env_loader.py file to merge the development and test contexts into a single local context.

1. Modify src/config/env_loader.py

Update the path_map to have a single entry for all local work. You can point it to whichever .env file you prefer to use as the single source of truth.

File: src/config/env_loader.py

Python

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

def load_environments():
    """
    Loads environment variables from a context-specific .env file.
    
    - 'local': Unified context for all local development, including testing.
    - Unset/Other: Production context for GCP, loads no .env file.
    """
    context = os.getenv("ENV_CONTEXT", "production").lower()
    
    # --- CHANGE IS HERE ---
    # Simplified map for a single local environment
    path_map = {
        "local": Path.home() / "work" / "env" / ".env_cwe_chatbot"
    }
    # If you prefer to use the repo-local file for testing, you could use:
    # "local": Path(".env.test.local")
    # ----------------------

    if context not in path_map:
        logger.info(
            f"ENV_CONTEXT is '{context}'. No .env file will be loaded. "
            "Assuming production environment."
        )
        return

    path = path_map[context].resolve()

    if not path.exists():
        logger.warning(
            f"ENV_CONTEXT is '{context}', but the expected file was not found at: {path}"
        )
        return

    load_dotenv(dotenv_path=path)
    logger.info(f"✅ Loaded environment variables from: {path}")

2. Update Your Workflow

Now, for any local activity—whether running the app or running Playwright tests—you'll use the same command:

Bash

export ENV_CONTEXT=local

# For running the app
chainlit run ...

# For running tests
playwright test
This merges the two activities under one configuration. The main trade-off is the loss of test isolation.

