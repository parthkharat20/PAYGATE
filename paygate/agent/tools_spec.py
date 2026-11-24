"""
OpenAI/Anthropic tool schema specifications for the Payment Operations Agent.
"""

PAYMENT_AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_document",
            "description": "Read the text and metadata of an enterprise document (e.g., supplier invoice, shipping notice, email).",
            "parameters": {
                "type": "object",
                "properties": {
                    "doc_id": {
                        "type": "string",
                        "description": "Identifier of the document to inspect."
                    }
                },
                "required": ["doc_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_order",
            "description": "Retrieve current ERP order status, remaining authorized balance, and merchant bindings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {
                        "type": "string",
                        "description": "Identifier of the order to inspect."
                    }
                },
                "required": ["order_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_capture",
            "description": "Capture authorized funds upon shipment or delivery of items.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Order identifier."},
                    "amount": {"type": "string", "description": "Decimal monetary amount to capture."},
                    "currency": {"type": "string", "description": "Three-letter ISO currency code (e.g. EUR)."},
                    "recipient_id": {"type": "string", "description": "Target merchant or bank account identifier."},
                    "idempotency_key": {"type": "string", "description": "Unique key to prevent duplicate processing."}
                },
                "required": ["order_id", "amount", "currency", "recipient_id", "idempotency_key"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "void_authorization",
            "description": "Void an active authorization hold if an order is cancelled before fulfillment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Order identifier."},
                    "idempotency_key": {"type": "string", "description": "Unique key."}
                },
                "required": ["order_id", "idempotency_key"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "issue_refund",
            "description": "Issue a refund against settled/captured funds for damaged or returned merchandise.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Order identifier."},
                    "amount": {"type": "string", "description": "Refund amount."},
                    "currency": {"type": "string", "description": "Currency code."},
                    "idempotency_key": {"type": "string", "description": "Unique key."}
                },
                "required": ["order_id", "amount", "currency", "idempotency_key"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_consent",
            "description": "Update buyer workflow consent state (WAIT, SWAP, CANCEL, APPROVED).",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "Order identifier."},
                    "consent_state": {
                        "type": "string",
                        "enum": ["WAIT", "SWAP", "CANCEL", "APPROVED"],
                        "description": "New consent state."
                    }
                },
                "required": ["order_id", "consent_state"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_notification",
            "description": "Send status update or notification to a buyer or supplier email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Email address of recipient."},
                    "message": {"type": "string", "description": "Message content."}
                },
                "required": ["recipient", "message"]
            }
        }
    }
]
