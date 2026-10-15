# #44 수정 코드 검증 및 운영 확인

## 기준과 실행 경로

2026-10-14 확인. develop, HEAD = upstream/develop
`69dfdaa7b49fdf68e10acda2a5cf0b35d5be8e80` (#40 merge).
origin/develop = `3da1b7cdccdbbe69c3d1f3e57ac49b5a8c529d07` (#39).
두 remote fetch 완료. 시작 시 미커밋 변경 없음. 저장소 내 AGENTS.md 파일 없음;
사용자 제공 지침 적용. 커밋/push/PR/배포 없음.

실행 경로: `run_analysis_job` → `enrich_finding_with_explanation` →
`generate_explanation` → Claude tool 응답 DTO 검증 → `ensure_fix_examples` →
`build_success_callback_payload` → `SpringCallbackClient.send_success`.
LLM 실패는 기존 한국어 fallback 설명을 유지하고 코드 예시를 비운다.

## 원인과 변경

- 이전 ensure_fix_examples는 기존 예시를 검증 없이 통과시키고, 빈 예시를
  일반 한국어 문장 또는 무조건 Java PreparedStatement 코드로 채웠다.
  이제 대상 파일 언어와 문법을 확인한 예시만 남기고 빈 배열을 유지한다.
- prompt는 한국어 설명 지시와 코드 생성 지시가 모호했고 tool schema는
  minItems=1이었다. 이제 설명 필드만 한국어, 코드 값은 대상 언어 코드/설정만,
  생성 불가 시 빈 배열, recommendation 유지로 명시한다.
- DTO에서 optional 예시의 잘못된 타입/필수 필드 누락은 해당 예시만 제거한다.
  설명 필드 자체가 잘못된 응답은 기존 Claude 오류/fallback 경로를 따른다.
- Python AST, Java/JavaScript/TypeScript/TSX tree-sitter 문법 파서,
  YAML safe_load, JSON parser를 사용한다. 한글 주석/문자열과 세미콜론 없는
  Python/JS/YAML을 허용한다. 완전한 단일 fence는 제거한 뒤 검증하며,
  fence 밖 설명·여러 fence·다른 언어 label은 제외한다.
- vulnerableCode도 같은 검증을 적용하고 유효하지 않으면 null로 보낸다.
- 원본 코드나 LLM 응답을 신규 검증 로그에 출력하지 않는다.

## BE/FE 계약

기존 callback 필드 이름/구조를 유지한다. 코드 미생성은 분석 실패가 아니다.

```json
{
  "analysisId": 11,
  "repositoryId": 22,
  "status": "COMPLETED",
  "findings": [{
    "tool": "SEMGREP",
    "type": "SQL_INJECTION",
    "cweId": "CWE-89",
    "severity": "HIGH",
    "filePath": "src/main.py",
    "lineStart": 10,
    "lineEnd": null,
    "message": "사용자 입력이 SQL 쿼리에 결합됩니다.",
    "evidence": null,
    "summary": "SQL 인젝션 취약점이 탐지되었습니다.",
    "rootCause": "사용자 입력과 쿼리 구조가 분리되지 않습니다.",
    "impact": "허가되지 않은 데이터 접근이 발생할 수 있습니다.",
    "recommendation": "사용 중인 DB 드라이버의 매개변수화 쿼리를 사용하세요.",
    "fixExamples": [],
    "references": [],
    "referenceDocuments": []
  }],
  "summary": {"totalCount": 1},
  "failedScanners": []
}
```

Claude 자체가 실패하면 위 설명 필드는 기존 fallback 문구가 되며, fixExamples는
동일하게 빈 배열이다. 새 상태/오류 필드를 추가하지 않았다.

로컬 BE 소스 확인:
`AnalysisCallbackFinding`에는 fixExamples 최소 개수 제약이 없다.
`AnalysisFindingPersistenceService.resolveFixCode`는 빈 배열이면 null을 반환한다.
recommendation은 fixSummary에 독립 저장된다.
`AnalysisResult.fixCode`는 nullable이고 `AnalysisResultRepositoryImpl`은 상세 조회에
fixCode/fixSummary를 그대로 투영한다. 로컬 코드 기준으로 저장·조회와 호환된다.
운영 스키마/API가 이 코드와 일치하는지는 별도 확인해야 한다.

FE 전달: fixCode가 null/빈 문자열이면 코드 하이라이트·복사 버튼을 숨기고
“수정 코드 예시를 생성하지 못했습니다. 아래 수정 안내를 확인하세요.”를 표시한다.
fixSummary/recommendation과 취약점 설명은 계속 표시한다. 일반 설명을 코드 영역의
대체값으로 채우지 않는다. FE 구현과 실제 화면은 이번 작업에서 검증하지 않았다.

## 로컬 검증

최종 결과: 전체 72개 테스트 통과(추가 회귀 테스트 13개), git diff --check 통과.

```sh
venv/bin/python -m unittest tests.services.llm.test_fix_examples tests.jobs.test_analysis_job -q
venv/bin/python -m unittest discover -s tests -q
git diff --check
```

회귀 범위: 정상 Claude 코드, Python/Java/JS/TS/TSX/YAML/JSON,
한글 주석·문자열, 문장·빈 문자열·주석만 있는 예시, 문법 오류,
중첩 설명 문장, 단일 fence 정규화/혼합 설명 거부, 언어 불일치/미지원 언어,
잘못된 DTO 예시, 잘못된 첫 예시 다음 정상 예시, 비Java SQLi,
빈 배열과 Claude 실패의 COMPLETED callback, 실제 Worker orchestration의
LLM 실패 시 성공 callback 유지. 모든 외부 LLM/callback/DB 경로는 mock 처리한다.

## 운영에서 수행할 읽기 전용 확인 (이번 작업에서는 미실행)

1. 배포 의존성 두 requirements에 고정한 PyYAML/tree-sitter 패키지가 Worker
   이미지에 설치되는지 확인한다. Docker/CodeQL 설치 및 진행률 기능은 수정하지 않았다.
2. 기존 문제 analysisId·analysisResultId·발생 시각을 확보하고 동일 구간 로그와
   저장값을 대조한다. 현재 DB 값만으로 fallback/Claude를 확정하지 않는다.

```sh
# 운영 담당자가 실제 Worker container 이름과 시간 범위를 지정
# 외부 LLM 호출 또는 분석 재실행을 하지 않고 기존 로그만 조회
docker logs --since "$INCIDENT_START" --until "$INCIDENT_END" "$WORKER_CONTAINER" 2>&1 |
   rg 'Claude explanation generation failed|Omitting invalid fix example|Omitting malformed|Finding enrichment|analysis_id='
```

```sql
BEGIN TRANSACTION READ ONLY;
SELECT ar.analysis_result_id, v.analysis_id, v.vulnerability_type, v.cwe_id,
       ar.fix_code, ar.fix_summary, ar.summary, ar.description
FROM analysis_results ar
JOIN vulnerabilities v ON v.vulnerability_id = ar.vulnerability_id
WHERE ar.analysis_result_id = :analysis_result_id;

-- 같은 분석의 미생성 코드와 설명 보존 상태 확인
SELECT ar.analysis_result_id, ar.fix_code IS NULL AS no_fix_code,
       ar.fix_summary IS NOT NULL AS has_fix_summary
FROM analysis_results ar
JOIN vulnerabilities v ON v.vulnerability_id = ar.vulnerability_id
WHERE v.analysis_id = :analysis_id;
ROLLBACK;
```

`:analysis_result_id`, `:analysis_id`는 조회 도구의 바인딩 값으로 지정한다.
SQL의 has_fix_summary는 NULL 여부만 확인하므로 실제 안내 내용도 첫 쿼리로 확인한다.

3. 권한 있는 운영 담당자가 기존 결과 상세 API를 조회한다.

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$BE_BASE_URL/api/repositories/$REPOSITORY_ID/analysis/issues/$ANALYSIS_RESULT_ID"
```

응답 fixCode=null, fixSummary 유지와 FE의 코드 미생성 표시를 확인한다.
4. 이미 저장된 잘못된 fix_code는 이번 수정으로 자동 교정되지 않는다. 기존 결과의
   정정/재분석은 별도 승인과 작업으로 다룬다. 운영 데이터 변경 SQL은 제공하지 않는다.

## 검증 한계

문법 검사는 보안 효과, 실제 컴파일, API/변수 존재, 원본 저장소에 대한 적용 가능성을
증명하지 않는다. 언어 간 공통 문법은 파서만으로 출처 언어를 확정할 수 없다.
YAML/JSON 형식에 맞춘 설명은 실제 설정과 문법적으로 구별할 수 없으므로 의미 검토가
필요하다. 미지원 확장자, 파싱 불가능한 부분 코드, 단독 표현식/문자열은 보수적으로
미생성 처리한다. 별도 언어/설정 형식 지원은 필요 사례를 기준으로 추가한다.

추천 커밋 메시지: `fix: 수정 코드 fallback 제거 및 대상 언어 검증 (#44)`
