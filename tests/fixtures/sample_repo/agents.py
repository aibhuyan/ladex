"""Fixture: agent/orchestration + inference API usage."""

import openai
from anthropic import Anthropic
from langchain.agents import initialize_agent

client = openai.OpenAI()
ac = Anthropic()

MODEL = "gpt-4o"
agent = initialize_agent(tools=[], llm=None)
reply = ac.messages.create(model="claude-3-5-sonnet-latest", max_tokens=10, messages=[])
