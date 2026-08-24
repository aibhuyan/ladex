"""Fixture: vector store usage. `pc.Index(...)` is an instance method — head `pc` is a
local variable, not an import binding, so it must NOT resolve to `pinecone.Index`."""

from pinecone import Pinecone

pc = Pinecone(api_key="local-key")
index = pc.Index("demo")
