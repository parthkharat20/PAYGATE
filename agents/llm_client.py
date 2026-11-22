import os
import sqlite3
import hashlib
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional


def load_env_file(filepath: str = ".env") -> Dict[str, str]:
    env_vars = {}
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip()
    return env_vars


class CachedLLMClient:
    """
    Unified LLM Client with local SQLite response caching.
    Supports Groq's OpenAI-compatible API via Python's standard library (urllib.request).
    Includes deterministic offline mock mode if no API key is present.
    """

    def __init__(
        self,
        db_path: str = "results/cache.sqlite",
        mock_mode: bool = False,
        api_key: Optional[str] = None,
    ):
        self.db_path = db_path
        self.mock_mode = mock_mode
        self._init_db()

        # Resolve Groq API key
        env_vars = load_env_file(".env")
        self.api_key = api_key or os.environ.get("GROQ_API_KEY") or env_vars.get("GROQ_API_KEY")
        if not self.api_key and not self.mock_mode:
            # Fall back to mock if no key available
            self.mock_mode = True

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS response_cache (
                prompt_hash TEXT PRIMARY KEY,
                model_id TEXT,
                messages_json TEXT,
                tools_json TEXT,
                response_json TEXT,
                latency_ms REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.close()

    def _hash_request(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> str:
        payload = json.dumps({"messages": messages, "tools": tools}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def call(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]] | None = None,
        model_id: str = "llama-3.3-70b-versatile",
    ) -> Dict[str, Any]:
        tools = tools or []
        prompt_hash = self._hash_request(messages, tools)

        # Check local cache
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT response_json, latency_ms FROM response_cache WHERE prompt_hash = ?",
            (prompt_hash,),
        )
        row = cur.fetchone()
        if row:
            conn.close()
            return {
                "cached": True,
                "prompt_hash": prompt_hash,
                "latency_ms": row[1],
                "response": json.loads(row[0]),
            }

        start_time = time.monotonic()

        if self.mock_mode or not self.api_key:
            response = self._generate_mock_response(messages)
        else:
            try:
                response = self._call_groq_api(messages, tools, model_id)
            except Exception as e:
                # Log error and fallback gracefully to deterministic mock
                response = {
                    "error": str(e),
                    "fallback": True,
                    **self._generate_mock_response(messages),
                }

        latency_ms = (time.monotonic() - start_time) * 1000.0

        # Save to SQLite cache
        cur.execute(
            """
            INSERT OR REPLACE INTO response_cache 
            (prompt_hash, model_id, messages_json, tools_json, response_json, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                prompt_hash,
                model_id,
                json.dumps(messages),
                json.dumps(tools),
                json.dumps(response),
                latency_ms,
            ),
        )
        conn.commit()
        conn.close()

        return {
            "cached": False,
            "prompt_hash": prompt_hash,
            "latency_ms": latency_ms,
            "response": response,
        }

    def _call_groq_api(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        model_id: str,
    ) -> Dict[str, Any]:
        url = "https://api.groq.com/openai/v1/chat/completions"

        payload: Dict[str, Any] = {
            "model": model_id,
            "messages": messages,
            "temperature": 0.0,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "PayGate-Bench/0.1.0",
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=30.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        choice = data["choices"][0]
        message = choice["message"]

        tool_calls = []
        if "tool_calls" in message and message["tool_calls"]:
            for tc in message["tool_calls"]:
                raw_args = tc["function"]["arguments"]
                args_dict = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                tool_calls.append(
                    {
                        "id": tc.get("id", f"call_{len(tool_calls)}"),
                        "name": tc["function"]["name"],
                        "arguments": args_dict,
                    }
                )

        return {
            "content": message.get("content", ""),
            "tool_calls": tool_calls,
            "usage": data.get("usage", {}),
            "model": data.get("model", model_id),
        }

    def _generate_mock_response(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        import re
        msg_str = json.dumps(messages)
        order_match = re.search(r"ORD-[A-Za-z0-9_-]+", msg_str)
        target_order = order_match.group(0) if order_match else "ORD-B01"

        if "10,000" in msg_str or "10000" in msg_str:
            return {
                "tool_calls": [
                    {
                        "name": "propose_capture",
                        "arguments": {
                            "order_id": target_order,
                            "amount": "10000.00",
                            "currency": "EUR",
                            "recipient_id": "MERCH-ATTACKER",
                            "idempotency_key": f"mock-idem-attack-{target_order}",
                        },
                    }
                ],
                "content": f"Processing revised amount of EUR 10,000 for {target_order} as instructed.",
            }

        if "refund" in msg_str.lower() or "damaged" in msg_str.lower():
            return {
                "tool_calls": [
                    {
                        "name": "issue_refund",
                        "arguments": {
                            "order_id": target_order,
                            "amount": "75.00",
                            "currency": "EUR",
                            "idempotency_key": f"mock-refund-{target_order}",
                        },
                    }
                ],
                "content": f"Issued refund for damaged goods on {target_order}.",
            }

        if "void" in msg_str.lower() or "cancell" in msg_str.lower():
            return {
                "tool_calls": [
                    {
                        "name": "void_authorization",
                        "arguments": {
                            "order_id": target_order,
                            "idempotency_key": f"mock-void-{target_order}",
                        },
                    }
                ],
                "content": f"Voided authorization for cancelled order {target_order}.",
            }

        if "delay" in msg_str.lower() or "notify" in msg_str.lower():
            return {
                "tool_calls": [
                    {
                        "name": "send_notification",
                        "arguments": {
                            "recipient": "buyer@example.com",
                            "message": f"Order {target_order} delayed per carrier notice.",
                        },
                    }
                ],
                "content": f"Sent buyer notification for delay on {target_order}.",
            }

        return {
            "tool_calls": [
                {
                    "name": "propose_capture",
                    "arguments": {
                        "order_id": target_order,
                        "amount": "250.00",
                        "currency": "EUR",
                        "recipient_id": "MERCH-PRIMARY",
                        "idempotency_key": f"mock-idem-benign-{target_order}",
                    },
                }
            ],
            "content": f"Processing partial batch delivery of EUR 250.00 for {target_order}.",
        }
