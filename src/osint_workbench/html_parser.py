"""Bounded syntactic HTML extraction, not a browser or readability engine.

Accepted documents have one explicit head/title followed by one explicit body.
UTF-8 is mandatory; optional simple HTML doctype never resolves external entities.
No CSS evaluation, URL selection, script execution or resource acquisition occurs.
"""

import json
import sys
from html.parser import HTMLParser

from .errors import WorkbenchError

MAX_HTML = 10 * 1024 * 1024
MAX_RESULT = 16 * 1024 * 1024
_HIDDEN = {"script", "style", "iframe", "object", "template"}
_VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
_BREAKS = {
    "p",
    "br",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "tr",
    "td",
    "th",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "aside",
    "blockquote",
    "pre",
}


class _Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.head = self.title = self.body = False
        self.head_count = self.title_count = self.body_count = 0
        self.hidden = []
        self.title_parts = []
        self.body_parts = []
        self.characters = 0

    def invalid(self):
        raise WorkbenchError("HTML_STRUCTURE_UNSUPPORTED")

    def handle_decl(self, decl):
        if decl.lower().split() != ["doctype", "html"]:
            self.invalid()

    def unknown_decl(self, data):
        self.invalid()

    def handle_startendtag(self, tag, attrs):
        # HTML does not close nonvoid elements with '/>'. Treating <script/>
        # as an empty region would expose its subsequent content as body text.
        if tag not in _VOID:
            self.invalid()
        self.handle_starttag(tag, attrs)

    def handle_starttag(self, tag, attrs):
        if self.hidden:
            if tag in _HIDDEN:
                self.hidden.append(tag)
            return
        if tag in _HIDDEN:
            self.hidden.append(tag)
        elif tag == "head":
            if self.head_count or self.body_count:
                self.invalid()
            self.head_count += 1
            self.head = True
        elif tag == "title":
            if not self.head or self.title_count:
                self.invalid()
            self.title_count += 1
            self.title = True
        elif tag == "body":
            if self.head or self.body_count or self.title_count != 1:
                self.invalid()
            self.body_count += 1
            self.body = True
        elif self.body and tag in _BREAKS:
            self.body_parts.append("\n")

    def handle_endtag(self, tag):
        if self.hidden:
            if tag in _HIDDEN:
                if tag != self.hidden[-1]:
                    self.invalid()
                self.hidden.pop()
            return
        if tag == "title":
            if not self.title:
                self.invalid()
            self.title = False
        elif tag == "head":
            if not self.head or self.title:
                self.invalid()
            self.head = False
        elif tag == "body":
            if not self.body:
                self.invalid()
            self.body = False
        elif self.body and tag in _BREAKS:
            self.body_parts.append("\n")

    def handle_data(self, data):
        if self.hidden:
            return
        if self.title or self.body:
            self.characters += len(data)
            if self.characters > 1_002_000:
                raise WorkbenchError("HTML_TEXT_LIMIT")
            (self.title_parts if self.title else self.body_parts).append(data)


def parse(raw):
    if not isinstance(raw, bytes):
        raise WorkbenchError("HTML_PARSE_FAILED")
    if len(raw) > MAX_HTML:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    try:
        text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeError:
        raise WorkbenchError("HTML_ENCODING_UNSUPPORTED") from None
    if "\x00" in text:
        raise WorkbenchError("HTML_PARSE_FAILED")
    parser = _Document()
    parser.feed(text)
    parser.close()
    if (
        parser.head
        or parser.title
        or parser.body
        or parser.hidden
        or (parser.head_count, parser.title_count, parser.body_count) != (1, 1, 1)
    ):
        raise WorkbenchError("HTML_STRUCTURE_UNSUPPORTED")
    title = " ".join("".join(parser.title_parts).split())
    body = "\n".join(
        line.strip() for line in "".join(parser.body_parts).splitlines() if line.strip()
    )
    if not title or not body:
        raise WorkbenchError("HTML_EMPTY_DOCUMENT")
    if len(title) > 2000 or len(body) > 1_000_000:
        raise WorkbenchError("HTML_TEXT_LIMIT")
    return {"title": title, "text": body}


def main():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        result = json.dumps(parse(sys.stdin.buffer.read(MAX_HTML + 1))).encode()
        if len(result) > MAX_RESULT:
            raise WorkbenchError("HTML_RESULT_LIMIT")
        sys.stdout.buffer.write(result)
    except WorkbenchError as exc:
        sys.stdout.write(json.dumps({"error": exc.code}))
        raise SystemExit(1) from None
    except Exception:
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
