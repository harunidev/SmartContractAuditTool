from setuptools import find_packages, setup

with open("requirements.txt") as f:
    install_requires = [l.strip() for l in f if l.strip() and not l.startswith("#")]

setup(
    name="smart-contract-audit-tool",
    version="1.0.0",
    description="Solidity/EVM smart contract security auditor — static patterns + Claude AI",
    author="harunidev",
    url="https://github.com/harunidev/SmartContractAuditTool",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    package_data={
        "audit_tool": ["web/templates/*.html"],
    },
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "audit-contract=audit_tool.cli:main",
        ]
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="solidity evm ethereum security audit smart-contract static-analysis claude ai",
)
