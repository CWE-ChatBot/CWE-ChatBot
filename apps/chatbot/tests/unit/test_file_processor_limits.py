import asyncio

from src.file_processor import FileProcessor


class DummyFile:
    def __init__(self, name: str, content: bytes, mime: str):
        self.name = name
        self.content = content
        self.mime = mime
        self.type = "file"


class DummyMessage:
    def __init__(self, elements):
        self.elements = elements


def test_file_processor_type_and_size_gating():
    fp = FileProcessor()
    # Oversized PDF (11MB)
    big = DummyFile("big.pdf", b"0" * (11 * 1024 * 1024), "application/pdf")
    # Unsupported type
    txt = DummyFile("notes.txt", b"hello", "text/plain")

    msg = DummyMessage([big, txt])

    content = asyncio.get_event_loop().run_until_complete(fp.process_attachments(msg))
    assert content is not None
    assert "exceeds the" in content
