from pathlib import Path
import re
import xml.etree.ElementTree as ET

from app.services.rag.documents import RagSourceDocument, RagSourceType

CWE_NAMESPACE = {"cwe": "http://cwe.mitre.org/cwe-7"}
OWASP_GITHUB_BASE_URL = (
    "https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets"
)


# OWASP markdown 파일 로딩
def load_owasp_documents(raw_dir: Path) -> list[RagSourceDocument]:
    documents: list[RagSourceDocument] = []

    for path in sorted(raw_dir.glob("*.md")):
        # 라이선스 파일은 색인 제외
        if path.name.upper().startswith("LICENSE"):
            continue

        content = path.read_text(encoding="utf-8")
        documents.append(
            RagSourceDocument(
                source_type=RagSourceType.OWASP,
                source_id=path.stem,
                title=extract_markdown_title(content, path.stem),
                content=content,
                url=f"{OWASP_GITHUB_BASE_URL}/{path.name}",
                metadata={"file_name": path.name},
            )
        )

    return documents


# CWE XML entry 로딩
def load_cwe_documents(xml_path: Path) -> list[RagSourceDocument]:
    root = ET.parse(xml_path).getroot()
    version = root.attrib.get("Version")
    documents: list[RagSourceDocument] = []

    for weakness in root.findall("cwe:Weaknesses/cwe:Weakness", CWE_NAMESPACE):
        cwe_id = weakness.attrib["ID"]
        name = weakness.attrib["Name"]
        title = f"CWE-{cwe_id}: {name}"
        content = build_cwe_content(weakness, title)

        documents.append(
            RagSourceDocument(
                source_type=RagSourceType.CWE,
                source_id=f"CWE-{cwe_id}",
                title=title,
                content=content,
                url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                metadata={
                    "cwe_id": f"CWE-{cwe_id}",
                    "version": version,
                    "abstraction": weakness.attrib.get("Abstraction"),
                    "status": weakness.attrib.get("Status"),
                },
            )
        )

    return documents


# markdown H1 제목 추출
def extract_markdown_title(content: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+)$", content, flags=re.MULTILINE)
    if match:
        return match.group(1).strip()

    return fallback.replace("_", " ")


# CWE XML 필드를 검색용 본문으로 조합
def build_cwe_content(weakness: ET.Element, title: str) -> str:
    sections = [
        ("Title", title),
        ("Description", find_text(weakness, "cwe:Description")),
        ("Extended Description", find_text(weakness, "cwe:Extended_Description")),
        ("Background Details", join_child_texts(weakness, "cwe:Background_Details/*")),
        ("Common Consequences", build_common_consequences(weakness)),
        ("Potential Mitigations", build_potential_mitigations(weakness)),
        ("Detection Methods", build_detection_methods(weakness)),
    ]

    return "\n\n".join(
        f"## {heading}\n{text}"
        for heading, text in sections
        if text
    )


# XML 단일 노드 텍스트 추출
def find_text(element: ET.Element, path: str) -> str | None:
    child = element.find(path, CWE_NAMESPACE)
    if child is None:
        return None

    return normalize_text(" ".join(child.itertext()))


# XML 하위 노드 목록을 bullet 텍스트로 변환
def join_child_texts(element: ET.Element, path: str) -> str | None:
    values = [
        normalize_text(" ".join(child.itertext()))
        for child in element.findall(path, CWE_NAMESPACE)
    ]
    values = [value for value in values if value]
    return "\n".join(f"- {value}" for value in values) or None


# CWE 영향 범위/영향/메모 조합
def build_common_consequences(weakness: ET.Element) -> str | None:
    values: list[str] = []

    for consequence in weakness.findall(
        "cwe:Common_Consequences/cwe:Consequence",
        CWE_NAMESPACE,
    ):
        scope = join_direct_children(consequence, "cwe:Scope")
        impact = join_direct_children(consequence, "cwe:Impact")
        note = find_text(consequence, "cwe:Note")
        parts = [part for part in [scope, impact, note] if part]
        if parts:
            values.append(" - ".join(parts))

    return "\n".join(f"- {value}" for value in values) or None


# CWE 완화 방법 조합
def build_potential_mitigations(weakness: ET.Element) -> str | None:
    values: list[str] = []

    for mitigation in weakness.findall(
        "cwe:Potential_Mitigations/cwe:Mitigation",
        CWE_NAMESPACE,
    ):
        phase = join_direct_children(mitigation, "cwe:Phase")
        description = find_text(mitigation, "cwe:Description")
        parts = [part for part in [phase, description] if part]
        if parts:
            values.append(" - ".join(parts))

    return "\n".join(f"- {value}" for value in values) or None


# CWE 탐지 방법 조합
def build_detection_methods(weakness: ET.Element) -> str | None:
    values: list[str] = []

    for method in weakness.findall(
        "cwe:Detection_Methods/cwe:Detection_Method",
        CWE_NAMESPACE,
    ):
        method_name = find_text(method, "cwe:Method")
        description = find_text(method, "cwe:Description")
        parts = [part for part in [method_name, description] if part]
        if parts:
            values.append(" - ".join(parts))

    return "\n".join(f"- {value}" for value in values) or None


# 같은 이름의 직접 하위 노드 값 병합
def join_direct_children(element: ET.Element, path: str) -> str | None:
    values = [
        normalize_text(" ".join(child.itertext()))
        for child in element.findall(path, CWE_NAMESPACE)
    ]
    values = [value for value in values if value]
    return ", ".join(values) or None


# XML 공백 정규화
def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()
