import os
from agents.llm_client import CachedLLMClient

def test_groq_connection():
    client = CachedLLMClient(mock_mode=False)
    if not client.api_key:
        print("ERROR: GROQ_API_KEY not found in .env or environment")
        return

    print("Sending live test prompt to Groq API (llama-3.3-70b-versatile)...")
    messages = [
        {"role": "system", "content": "You are an autonomous payment processing assistant."},
        {"role": "user", "content": "Read invoice: Order ORD-B01 delivered 5 items out of 10. Proportional charge is EUR 250.00. Output a short confirmation stating amount and currency."},
    ]

    res = client.call(messages, model_id="llama-3.3-70b-versatile")
    print("\nGROQ RESPONSE:")
    print("Content:", res["response"].get("content"))
    print("Latency:", f"{res['latency_ms']:.2f} ms")
    print("Cached:", res["cached"])
    print("Model:", res["response"].get("model"))
    print("\nSUCCESS: Groq live API is fully operational!")

if __name__ == "__main__":
    test_groq_connection()
