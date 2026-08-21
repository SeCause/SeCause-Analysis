import re

from app.services.rag.documents import RagDocumentChunk, RagSourceDocument, RagSourceType

MIN_CHUNK_CHARS = 80
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
MARKDOWN_IMAGE_PATTERN = re.compile(r"!\[[^\]]*]\([^)]+\)")
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)]\(([^)]+)\)")
URL_ONLY_PATTERN = re.compile(r"^\s*[-*]?\s*https?://\S+\s*$")
EXCLUDED_OWASP_HEADING_PATTERN = re.compile(
    r"^#{1,6}\s+("
    r"authors?|contributors?|acknowledgements?|references?|related articles|"
    r"other cheatsheets|license|licensing"
    r")\b",
    flags=re.IGNORECASE,
)


# 문서 본문 전처리
def preprocess_document(document: RagSourceDocument) -> RagSourceDocument:
    content = document.content

    if document.source_type == RagSourceType.OWASP:
        content = remove_excluded_markdown_sections(content)

    content = normalize_markup_noise(content)

    return RagSourceDocument(
        source_type=document.source_type,
        source_id=document.source_id,
        title=document.title,
        content=content,
        url=document.url,
        metadata=document.metadata,
    )


# 문서 목록 전처리
def preprocess_documents(documents: list[RagSourceDocument]) -> list[RagSourceDocument]:
    return [preprocess_document(document) for document in documents]


# chunk 본문 전처리 및 품질 필터링
def preprocess_chunks(chunks: list[RagDocumentChunk]) -> list[RagDocumentChunk]:
    preprocessed: list[RagDocumentChunk] = []
    chunk_indexes_by_source: dict[tuple[RagSourceType, str], int] = {}

    for chunk in chunks:
        content = normalize_markup_noise(chunk.content)
        if not is_useful_chunk(content):
            continue

        # 같은 원본 문서 안에서만 chunk index 증가
        source_key = (chunk.source_type, chunk.source_id)
        chunk_index = chunk_indexes_by_source.get(source_key, 0)
        chunk_indexes_by_source[source_key] = chunk_index + 1

        preprocessed.append(
            RagDocumentChunk(
                source_type=chunk.source_type,
                source_id=chunk.source_id,
                chunk_index=chunk_index,
                title=chunk.title,
                content=content,
                url=chunk.url,
                metadata=chunk.metadata,
            )
        )

    return preprocessed


# 제외 대상 markdown section 제거
def remove_excluded_markdown_sections(content: str) -> str:
    lines = content.splitlines()
    kept_lines: list[str] = []
    skip_heading_level: int | None = None

    for line in lines:
        heading_level = markdown_heading_level(line)
        if heading_level is not None:
            if should_exclude_owasp_heading(line):
                skip_heading_level = heading_level
                continue

            if skip_heading_level is not None and heading_level <= skip_heading_level:
                skip_heading_level = None

        if skip_heading_level is not None:
            continue

        kept_lines.append(line)

    return "\n".join(kept_lines)


# markdown heading level 계산
def markdown_heading_level(line: str) -> int | None:
    match = re.match(r"^(#{1,6})\s+", line)
    return len(match.group(1)) if match else None


# OWASP 제외 heading 판별
def should_exclude_owasp_heading(line: str) -> bool:
    return EXCLUDED_OWASP_HEADING_PATTERN.match(line.strip()) is not None


# markdown/html 노이즈 정리
def normalize_markup_noise(content: str) -> str:
    content = MARKDOWN_IMAGE_PATTERN.sub("", content)
    content = MARKDOWN_LINK_PATTERN.sub(r"\1", content)
    content = HTML_TAG_PATTERN.sub(" ", content)

    lines = [
        normalize_inline_whitespace(line)
        for line in content.splitlines()
        if not URL_ONLY_PATTERN.match(line)
    ]

    content = "\n".join(lines)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


# 한 줄 내부 공백 정리
def normalize_inline_whitespace(value: str) -> str:
    return re.sub(r"[ \t]+", " ", value).strip()


# 너무 짧거나 정보량이 낮은 chunk 제외
def is_useful_chunk(content: str) -> bool:
    if len(content) < MIN_CHUNK_CHARS:
        return False

    alphanumeric_count = sum(character.isalnum() for character in content)
    return alphanumeric_count / max(len(content), 1) >= 0.25
