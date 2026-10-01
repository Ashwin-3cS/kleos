"""The eval harness: does a resolved record actually beat plain retrieval?

Step 0's exit test; see the root README, "Where this is going".
``python -m orchestrator.eval`` ingests a labelled synthetic corpus, runs the
same questions through the query graph and through a plain RAG baseline, and
prints the difference -- including a verdict that says to stop if resolution
does not help.
"""

from .harness import evaluate, format_report

__all__ = ["evaluate", "format_report"]
