"""
AI-powered audit layer using Claude API.
Sends contract source to Claude and parses structured vulnerability findings.
"""
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

import anthropic

from .static import Finding


SYSTEM_PROMPT = """You are an expert Solidity smart contract security auditor with deep knowledge of EVM internals, DeFi attack vectors, and common vulnerability patterns (SWC registry, OpenZeppelin, ConsenSys best practices).

When analyzing a smart contract, identify ALL security vulnerabilities, logic errors, and best-practice violations. For each finding output a JSON array with objects containing these exact keys:
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
- category: short category name (e.g. "Reentrancy", "Access Control")
- title: concise vulnerability title
- description: clear explanation of the vulnerability and attack scenario
- recommendation: concrete fix with code example if applicable
- line: line number (integer) or null if not applicable

Respond ONLY with a valid JSON array. No markdown fences, no explanations outside the array."""

USER_TEMPLATE = """Audit the following Solidity smart contract for security vulnerabilities:

```solidity
{source_code}
```

Return a JSON array of findings."""


class AIAuditor:
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-opus-4-7"):
        self.client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self.model = model

    def analyze(self, source_code: str) -> tuple[list[Finding], str]:
        """
        Returns (findings_list, raw_ai_summary).
        raw_ai_summary is the full narrative text for the report.
        """
        message = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": USER_TEMPLATE.format(source_code=source_code)}
            ],
        )

        raw = message.content[0].text.strip()

        # Strip markdown code fences if Claude wraps them anyway
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            # Best-effort: extract array from response
            match = re.search(r"\[.*\]", raw, re.DOTALL)
            items = json.loads(match.group(0)) if match else []

        findings = []
        for item in items:
            findings.append(
                Finding(
                    severity=item.get("severity", "INFO"),
                    category=item.get("category", "General"),
                    title=item.get("title", "Unknown"),
                    description=item.get("description", ""),
                    recommendation=item.get("recommendation", ""),
                    line=item.get("line"),
                    snippet=None,
                )
            )

        return findings, raw
