"""Ladex extension demo.

Open this file in the Extension Development Host (F5) and you should see inline Ladex
diagnostics on the AI-relevant lines below — and nothing on the ordinary Python.
Try editing: add `import transformers` and watch a new diagnostic appear as you type.
"""

import openai
from anthropic import Anthropic

client = openai.OpenAI()
ac = Anthropic()

MODEL = "gpt-4o"
reply = ac.messages.create(model="claude-3-5-sonnet-latest", max_tokens=10, messages=[])


# Ordinary Python below — Ladex stays silent here (ruthless silence).
def add(a: int, b: int) -> int:
    return a + b
