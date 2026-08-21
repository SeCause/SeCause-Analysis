import re

from app.services.rag.documents import RagDocumentChunk, RagSourceDocument, RagSourceType

DEFAULT_MAX_CHARS = 4000
DEFAULT_OVERLAP_CHARS = 300
HEADING_PATTERN = re.compile(r"^#{1,6}\s+.+$", flags=re.MULTILINE)


# 원본 문서를 chunk 목록으로 변환
def chunk_documents(
    documents: list[RagSourceDocument],
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap_chars: int = DEFAULT_OVERLAP_CHARS,
) -> list[RagDocumentChunk]:
    chunks: list[RagDocumentChunk] = []

    for document in documents:
        chunks.extend(
            chunk_document(
                document,
                max_chars=max_chars,
                overlap_chars=overlap_chars,
            )
        )

    return chunks


# source 타입별 chunking 전략 선택
def chunk_document(
    document: RagSourceDocument,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap_chars: int = DEFAULT_OVERLAP_CHARS,
) -> list[RagDocumentChunk]:
    if document.source_type == RagSourceType.OWASP:
        # OWASP markdown은 heading 기준으로 의미 단위 분리
        text_parts = split_markdown_by_heading(document.content)
    else:
        # CWE는 entry 하나를 기본 의미 단위로 사용
        text_parts = [document.content]

    chunk_texts: list[str] = []
    for text_part in text_parts:
        chunk_texts.extend(
            split_text(
                text_part,
                max_chars=max_chars,
                overlap_chars=overlap_chars,
            )
        )

    return [
        RagDocumentChunk(
            source_type=document.source_type,
            source_id=document.source_id,
            chunk_index=index,
            title=document.title,
            content=chunk_text,
            url=document.url,
            metadata=document.metadata,
        )
        for index, chunk_text in enumerate(chunk_texts)
        if chunk_text
    ]


# markdown heading 기준 section 분리
def split_markdown_by_heading(content: str) -> list[str]:
    matches = list(HEADING_PATTERN.finditer(content))
    if not matches:
        return [content.strip()] if content.strip() else []

    sections: list[str] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
        section = content[start:end].strip()
        if section:
            sections.append(section)

    preamble = content[: matches[0].start()].strip()
    if preamble:
        sections.insert(0, preamble)

    return sections


# 최대 길이를 넘지 않도록 문단 단위 분할
def split_text(
    content: str,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap_chars: int = DEFAULT_OVERLAP_CHARS,
) -> list[str]:
    content = content.strip()
    if not content:
        return []

    if len(content) <= max_chars:
        return [content]

    paragraphs = re.split(r"\n\s*\n", content)
    chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        if not paragraph:
            continue

        # 단일 문단이 너무 긴 경우 강제 분할
        if len(paragraph) > max_chars:
            if current:
                chunks.append(current.strip())
                current = ""
            chunks.extend(split_long_text(paragraph, max_chars, overlap_chars))
            continue

        candidate = f"{current}\n\n{paragraph}".strip() if current else paragraph
        if len(candidate) <= max_chars:
            current = candidate
            continue

        # chunk 경계에 overlap 추가
        chunks.append(current.strip())
        current = with_overlap(current, overlap_chars, paragraph)

    if current:
        chunks.append(current.strip())

    return chunks


# 긴 문단 강제 분할
def split_long_text(text: str, max_chars: int, overlap_chars: int) -> list[str]:
    chunks: list[str] = []
    start = 0
    step = max(max_chars - overlap_chars, 1)

    while start < len(text):
        chunks.append(text[start : start + max_chars].strip())
        start += step

    return [chunk for chunk in chunks if chunk]


# 이전 chunk 끝부분을 다음 chunk 앞에 붙임
def with_overlap(previous: str, overlap_chars: int, next_text: str) -> str:
    if overlap_chars <= 0:
        return next_text

    overlap = previous[-overlap_chars:].strip()
    return f"{overlap}\n\n{next_text}".strip() if overlap else next_text
