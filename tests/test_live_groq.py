"""
Live Groq API connectivity smoke test (runs when PAYGATE_RUN_LIVE_TESTS=1).
"""

import os
import pytest
from paygate.agent.llm_client import CachedLLMClient


def test_groq_connection(tmp_path):
    if os.getenv("PAYGATE_RUN_LIVE_TESTS") != "1":
        pytest.skip("Set PAYGATE_RUN_LIVE_TESTS=1 to run live network API smoke test")
    client = CachedLLMClient(db_path=str(tmp_path / "groq_test.sqlite"))
    if not os.getenv("GROQ_API_KEY"):
        pytest.skip("GROQ_API_KEY not configured")
    res = client.call(
        messages=[{"role": "user", "content": "Reply with OK"}],
        model_id="openai/gpt-oss-20b",
    )
    assert res["response"]["content"] is not None
