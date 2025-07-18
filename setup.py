#!/usr/bin/env python3
"""
Setup script for Advanced SQL Injection Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="advanced-sqli-scanner",
    version="1.0.0",
    author="Advanced SQLi Scanner Team",
    author_email="contact@example.com",
    description="A comprehensive SQL injection scanner with advanced features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/advanced-sqli-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "playwright": [
            "playwright>=1.40.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sqli-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.json", "*.md"],
        "payloads": ["*.txt"],
        "config": ["*.json"],
        "examples": ["*.py"],
    },
    zip_safe=False,
    keywords="sql injection, security, penetration testing, vulnerability scanner",
    project_urls={
        "Bug Reports": "https://github.com/example/advanced-sqli-scanner/issues",
        "Source": "https://github.com/example/advanced-sqli-scanner",
        "Documentation": "https://github.com/example/advanced-sqli-scanner/wiki",
    },
)
