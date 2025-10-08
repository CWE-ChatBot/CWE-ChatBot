#!/usr/bin/env python3
"""
Setup script for CWE Ingestion package.
This package provides data models and database utilities for CWE corpus processing.
"""

from setuptools import find_packages, setup

setup(
    name="cwe-ingestion",
    version="1.0.0",
    description="CWE corpus ingestion and data models",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "numpy>=1.24.0,<2.0.0",
        "psycopg[binary]>=3.1.0,<4.0.0",
        "pydantic>=2.0.0,<3.0.0",
        "google-generativeai>=0.7.0,<1.0.0",
        "cloud-sql-python-connector[pg8000]>=1.9.2,<2.0.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
