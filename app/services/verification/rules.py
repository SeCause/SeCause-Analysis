"""Deterministic checks for bounded, identifiable evidence snapshots."""

from app.schemas.verification import EvidenceKind, VerificationRequest

MAX_REQUEST_BYTES = 64 * 1024


class VerificationInputError(ValueError):
    """The request cannot be verified without correcting its structure."""


def validate_verification_request(request: VerificationRequest) -> None:
    if len(request.model_dump_json(by_alias=True).encode("utf-8")) > MAX_REQUEST_BYTES:
        raise VerificationInputError("Verification request exceeds 65536 UTF-8 bytes")

    evidence_ids: set[str] = set()
    for evidence in request.evidence:
        if evidence.evidence_id in evidence_ids:
            raise VerificationInputError("Evidence IDs must be unique")
        evidence_ids.add(evidence.evidence_id)

        has_start = evidence.line_start is not None
        has_end = evidence.line_end is not None
        if has_start != has_end:
            raise VerificationInputError("Code lineStart and lineEnd must be provided together")
        if has_start:
            if evidence.kind != EvidenceKind.CODE or not evidence.file_path:
                raise VerificationInputError("Line ranges require CODE evidence with filePath")
            if evidence.line_end < evidence.line_start:
                raise VerificationInputError("lineEnd must be greater than or equal to lineStart")
