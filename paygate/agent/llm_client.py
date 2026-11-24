"""
Cached LLM Client supporting OpenAI-compatible APIs, Groq, Ollama/vLLM, and Anthropic.
Uses SQLite persistent caching and time.perf_counter_ns() latency tracking.
"""

import os
import time
import json
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional


class CachedLLMClient:
    """
    Unified LLM Client with SQLite persistent caching and exact latency profiling.
    """

    def __init__(
        self,
        db_path: str = "results/cache.sqlite",
        mock_mode: bool = False,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.db_path = db_path
        self.mock_mode = mock_mode
        self.api_key = api_key or os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")
        self._init_db()

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_cache (
                    prompt_hash TEXT PRIMARY KEY,
                    model_id TEXT,
                    request_json TEXT,
                    response_json TEXT,
                    latency_ms REAL,
                    created_at REAL
                )
                """
            )
            conn.commit()

    def _hash_request(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]], model_id: str) -> str:
        payload = {"messages": messages, "tools": tools or [], "model_id": model_id}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def call(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_id: str = "llama-3.3-70b-versatile",
    ) -> Dict[str, Any]:
        """
        Executes an LLM inference call with caching and latency timing.
        """
        req_hash = self._hash_request(messages, tools, model_id)

        # Check SQLite cache
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT response_json, latency_ms FROM llm_cache WHERE prompt_hash = ?",
                (req_hash,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "response": json.loads(row[0]),
                    "latency_ms": row[1],
                    "cached": True,
                }

        # Mock Mode
        if self.mock_mode or not self.api_key:
            return self._mock_call(messages, tools)

        # Live API Call (OpenAI-compatible)
        t0 = time.perf_counter_ns()
        response_payload = self._live_call(messages, tools, model_id)
        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        # Store in cache
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO llm_cache
                (prompt_hash, model_id, request_json, response_json, latency_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    req_hash,
                    model_id,
                    json.dumps({"messages": messages, "tools": tools}),
                    json.dumps(response_payload),
                    latency_ms,
                    time.time(),
                ),
            )
            conn.commit()

        return {
            "response": response_payload,
            "latency_ms": latency_ms,
            "cached": False,
        }

    def _mock_call(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Deterministic mock response for offline CI."""
        last_msg = messages[-1]["content"] if messages else ""
        return {
            "response": {
                "content": "Mock LLM acknowledged request.",
                "tool_calls": [],
            },
            "latency_ms": 0.05,
            "cached": False,
        }

    def _live_call(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]], model_id: str) -> Dict[str, Any]:
        import urllib.request
        url = self.base_url or "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        body = {
            "model": model_id,
            "messages": messages,
            "temperature": 0.0,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        choice = data["choices"][0]["message"]
        tool_calls = []
        if "tool_calls" in choice and choice["tool_calls"]:
            for tc in choice["tool_calls"]:
                tool_calls.append({
                    "id": tc["id"],
                    "name": tc["function"]["name"],
                    "arguments": json.loads(tc["function"]["arguments"]),
                })

        return {
            "content": choice.get("content", ""),
            "tool_calls": tool_calls,
        }
