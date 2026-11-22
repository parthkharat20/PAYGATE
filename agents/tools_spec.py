"""
Agent tool specifications formatted for OpenAI / Groq tool calling.
"""

from typing import List, Dict, Any

PAYMENT_AGENT_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_document",
            "description": "Read a document (supplier invoice, shipping notice, or delivery status update).",
            "parameters": {
                "type": "object",
                "properties": {
                    "doc_id": {
                        "type": "string",
                        "description": "The unique ID of the document to inspect (e.g. 'DOC-NOT-01').",
                    }
                },
                "required": ["doc_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_order",
            "description": "Inspect current order status, authorized hold amount, remaining balance, and consent state.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {
                        "type": "string",
                        "description": "The unique ID of the order to inspect (e.g. 'ORD-B01').",
                    }
                },
                "required": ["order_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_capture",
            "description": "Capture funds against an authorization hold for an order.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Target order ID"},
                    "amount": {"type": "string", "description": "Decimal amount to capture (e.g. '250.00')"},
                    "currency": {"type": "string", "description": "3-letter currency code (e.g. 'EUR')"},
                    "recipient_id": {"type": "string", "description": "Recipient merchant identifier (e.g. 'MERCH-PRIMARY')"},
                    "idempotency_key": {"type": "string", "description": "Unique client-generated idempotency key"},
                },
                "required": ["order_id", "amount", "currency", "recipient_id", "idempotency_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "void_authorization",
            "description": "Void an authorization hold before funds are captured.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Target order ID"},
                    "idempotency_key": {"type": "string", "description": "Unique client-generated idempotency key"},
                },
                "required": ["order_id", "idempotency_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "issue_refund",
            "description": "Issue a refund against captured funds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Target order ID"},
                    "amount": {"type": "string", "description": "Decimal amount to refund"},
                    "currency": {"type": "string", "description": "3-letter currency code"},
                    "idempotency_key": {"type": "string", "description": "Unique client-generated idempotency key"},
                },
                "required": ["order_id", "amount", "currency", "idempotency_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_consent",
            "description": "Update buyer consent state (WAIT, SWAP, CANCEL, APPROVED).",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Target order ID"},
                    "consent_state": {
                        "type": "string",
                        "enum": ["WAIT", "SWAP", "CANCEL", "APPROVED"],
                        "description": "New buyer consent state",
                    },
                },
                "required": ["order_id", "consent_state"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_notification",
            "description": "Send an outbound notification message.",
            "parameters": {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Target recipient"},
                    "message": {"type": "string", "description": "Notification content"},
                },
                "required": ["recipient", "message"],
            },
        },
    },
]
