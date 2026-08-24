"""Fixture: model loaders (transformers + huggingface_hub) and a model id string."""

import transformers
from huggingface_hub import hf_hub_download

pipe = transformers.pipeline("sentiment-analysis")
weights = hf_hub_download(repo_id="bert-base-uncased", filename="pytorch_model.bin")

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
