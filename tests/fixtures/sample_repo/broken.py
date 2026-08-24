# Fixture: syntactically INVALID / half-typed code. tree-sitter must still recover the
# valid import above the breakage; the stdlib `ast` module would raise and find nothing.
import openai


def make_client(:            # <- deliberate syntax error, unfinished params
    client = openai.OpenAI(  # <- unterminated call
