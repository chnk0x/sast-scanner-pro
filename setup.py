from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="sast-vuln-scanner-pro",
    version="2.0.0",
    author="Cyber Security Senior Project",
    description="Senior-level AI-augmented SAST scanner with CVSS, SARIF, and multi-engine analysis.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pyyaml>=6.0",
        "openai>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "sast-scanner-pro=sast_scanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
