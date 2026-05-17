from setuptools import setup, find_packages

setup(
    name="smart-contract-audit-tool",
    version="1.0.0",
    description="Solidity/EVM smart contract security auditor (static + Claude AI)",
    author="harunidev",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "anthropic>=0.50.0",
        "flask>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "audit-contract=audit_tool.cli:main",
        ]
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
