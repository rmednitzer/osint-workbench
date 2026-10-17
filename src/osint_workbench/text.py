import hashlib
import re
from html.parser import HTMLParser

from .errors import WorkbenchError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "iframe", "object", "template"}:
            self.hidden += 1
        elif not self.hidden and tag in {"p", "br", "div", "h1", "h2", "li"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "iframe", "object", "template"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def html_text(value: str) -> str:
    parser = _Text()
    parser.feed(value)
    # Normalization is extraction, not a prompt-injection defense.
    return "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())


def evidence_span(text: str, proposed_quote: str) -> tuple[int, int, str]:
    """Return original-code-point offsets and the actual original quotation.

    Case folding can expand one character into several. A map preserves source
    coordinates; callers must store the returned literal, never the proposed one.
    Whitespace differences are accepted only between the proposed quote's tokens.
    """
    if not proposed_quote.strip() or len(text) > 1_000_000 or len(proposed_quote) > 10000:
        raise WorkbenchError("INVALID_EVIDENCE_QUOTE")
    folded, origins = [], []
    for index, char in enumerate(text):
        part = char.casefold()
        folded.append(part)
        origins.extend([index] * len(part))
    haystack = "".join(folded)
    pattern = r"\s+".join(re.escape(token.casefold()) for token in proposed_quote.split())
    match = re.search(pattern, haystack)
    if not match:
        raise WorkbenchError("EVIDENCE_NOT_FOUND")
    # Reject a match cutting through an expansion (e.g. one 's' within 'ß').
    if (match.start() and origins[match.start() - 1] == origins[match.start()]) or (
        match.end() < len(origins) and origins[match.end() - 1] == origins[match.end()]
    ):
        raise WorkbenchError("EVIDENCE_NOT_FOUND")
    start, end = origins[match.start()], origins[match.end() - 1] + 1
    return start, end, text[start:end]


def chunks(text: str, size: int = 1800, overlap: int = 150) -> list[dict]:
    """A versioned character chunker; does not claim token-aware chunking."""
    if not 32 <= size <= 20000 or not 0 <= overlap < size:
        raise WorkbenchError("INVALID_CHUNK_CONFIG")
    result = []
    for start in range(0, len(text), size - overlap):
        end = min(start + size, len(text))
        content = text[start:end]
        result.append(
            {
                "start": start,
                "end": end,
                "text": content,
                "sha256": digest(content.encode()),
                "chunker": "characters/1",
            }
        )
        if end == len(text):
            break
    return result
