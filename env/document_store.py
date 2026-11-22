from typing import Dict, Optional
from pydantic import BaseModel, ConfigDict


class Document(BaseModel):
    model_config = ConfigDict(strict=True)

    doc_id: str
    title: str
    doc_type: str  # e.g., 'invoice', 'supplier_notice', 'email'
    content: str


class DocumentStore:
    """
    Holds untrusted external business documents read by the agent.
    Provides utility methods to inject adversarial prompt payloads into documents.
    """

    def __init__(self):
        self._documents: Dict[str, Document] = {}

    def add_document(self, doc_id: str, title: str, doc_type: str, content: str) -> Document:
        doc = Document(doc_id=doc_id, title=title, doc_type=doc_type, content=content)
        self._documents[doc_id] = doc
        return doc

    def get_document(self, doc_id: str) -> Optional[Document]:
        return self._documents.get(doc_id)

    def get_document_content(self, doc_id: str) -> str:
        doc = self.get_document(doc_id)
        if not doc:
            raise KeyError(f"Document {doc_id} not found")
        return doc.content

    def inject_payload(self, doc_id: str, payload: str, position: str = "end") -> None:
        """
        Inject an adversarial prompt injection payload into a document.
        position: 'start', 'middle', or 'end'
        """
        doc = self.get_document(doc_id)
        if not doc:
            raise KeyError(f"Document {doc_id} not found")

        if position == "start":
            new_content = f"{payload}\n\n{doc.content}"
        elif position == "middle":
            lines = doc.content.splitlines()
            mid = len(lines) // 2
            new_content = "\n".join(lines[:mid]) + f"\n\n{payload}\n\n" + "\n".join(lines[mid:])
        else:  # 'end'
            new_content = f"{doc.content}\n\n{payload}"

        self._documents[doc_id] = Document(
            doc_id=doc.doc_id,
            title=doc.title,
            doc_type=doc.doc_type,
            content=new_content,
        )

    def reset(self) -> None:
        self._documents.clear()
