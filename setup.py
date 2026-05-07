from setuptools import setup, find_packages

setup(
    name="authpulse",
    version="1.0.0",
    description="Authorization testing framework for bug bounty hunting",
    author="AuthPulse",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "PyJWT>=2.6.0",
        "cryptography>=41.0.0",
        "click>=8.1.0",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "colorama>=0.4.6",
        "jsonpath-ng>=1.6.0",
    ],
    entry_points={
        "console_scripts": [
            "authpulse=authpulse.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
)
