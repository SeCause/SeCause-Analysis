# SeCause Analysis

<div align="center">

**AI 기반 코드 보안 취약점 분석 및 수정 가이드 제공 서비스**

<br />

<img
  width="600"
  alt="SeCause 서비스 화면"
  src="https://github.com/user-attachments/assets/5c663f26-90cf-470e-899c-52d6ca8a8250"
/>

<br />
<br />

[Website](https://www.secause.site) · [Organization](https://github.com/SeCause)

</div>

<br />

## About SeCause

**SeCause**는 AI 기반 코드 보안 취약점 분석 및 수정 가이드 제공 서비스입니다.

SeCause Analysis는 Backend로부터 분석 요청을 받아 비동기 작업으로 등록하고, 보안 분석 결과를 공통 형식으로 정규화·중복 제거한 뒤 근거 검색과 수정 가이드 보강 단계를 거쳐 Backend에 결과를 전달하는 **Analysis 서버**입니다.

> 현재 저장소는 분석 파이프라인의 인터페이스와 처리 흐름을 구현한 단계입니다. Semgrep, CodeQL, 인프라 분석기, RAG 검색, Claude 설명 생성, Spring 콜백은 스텁으로 구성되어 있으며 실제 외부 도구 및 API 호출은 아직 구현되어 있지 않습니다.

<br />

## 주요 기능

- `POST /api/internal/analyze`를 통한 내부 분석 요청 수신 및 Redis Queue 작업 등록
- GitHub 토큰을 Redis에 TTL 기반 참조값으로 임시 저장하고 작업 종료 후 삭제
- Semgrep, CodeQL, 인프라 설정 분석을 위한 공통 Runner 인터페이스와 실행 흐름 제공
- 분석 도구별 결과를 공통 Finding 스키마로 정규화
- CWE, 취약점 유형, 파일 경로, 시작 라인을 기준으로 중복 결과 제거
- Finding 정보를 기반으로 RAG 검색 질의를 구성하고 수정 가이드 보강 흐름 제공
- 분석 성공·실패 결과를 Spring Backend 콜백 스키마로 구성
- `/health`, `/docs` 엔드포인트를 통한 상태 및 API 명세 확인

<br />

## 아키텍처

```text
SeCause Backend
      │
      │ POST /api/internal/analyze
      ▼
FastAPI Analysis API
      │
      ├── GitHub Token ──► Redis 임시 저장 (TTL)
      │
      └── 분석 작업 ─────► Redis Queue
                              │
                              ▼
                           RQ Worker
                              │
                              ▼
              Semgrep / CodeQL / Infra Runner (Stub)
                              │
                              ▼
                    결과 정규화 및 중복 제거
                              │
                              ▼
                    RAG 근거 검색 (Stub)
                              │
                              ▼
                 설명 및 수정 가이드 생성 (Mock)
                              │
                              ▼
                 Spring Backend Callback (Stub)
```

<!-- 추후 아키텍처 이미지가 준비되면 이 위치에 추가합니다. -->

<br />

## Tech Stack

| 구분 | 기술 | 사용 목적 |
| --- | --- | --- |
| Language | Python 3.11 | 분석 서버 및 작업 처리 구현 |
| API | FastAPI 0.136.3, Uvicorn 0.24.0 | 내부 분석 API와 ASGI 서버 제공 |
| Validation | Pydantic Settings 2.1.0 | 요청·응답 스키마 및 환경 변수 검증 |
| Queue | Redis 5.0.1, RQ 1.15.1 | 비동기 분석 작업 큐와 토큰 참조 관리 |
| Database | SQLAlchemy 2.0.50, asyncpg 0.31.0 | PostgreSQL 비동기 연결 |
| Vector | pgvector 0.2.4 | 벡터 검색 연동을 위한 의존성 |
| HTTP | HTTPX 0.28.1 | HTTP 통신을 위한 의존성 |
| Repository | GitPython 3.1.50 | Git 저장소 처리를 위한 의존성 |
| AI SDK | Anthropic 0.7.0 | Claude 연동을 위한 의존성 및 환경 설정 |
| Container | Docker | Python 3.11 기반 API·Worker 이미지 빌드 |
| CI/CD | GitHub Actions, Docker Buildx | 컴파일 검증, 멀티 아키텍처 이미지 빌드 및 배포 |

<br />

## 주요 파일 구조

```text
SeCause-Analysis/
├── app/
│   ├── api/routes/        # 내부 분석 요청 API 라우트
│   ├── core/              # 환경 설정과 비동기 데이터베이스 연결
│   ├── jobs/              # Redis Queue, Worker, 분석 작업과 토큰 참조 관리
│   ├── schemas/           # 요청·응답, Finding, 파이프라인 데이터 모델
│   ├── services/
│   │   ├── callback/      # Spring Backend 콜백 스키마와 클라이언트 스텁
│   │   ├── llm/           # 설명 프롬프트와 수정 가이드 생성 Mock
│   │   ├── normalizer/    # 분석 결과 정규화 및 중복 제거
│   │   ├── rag/           # RAG 질의 생성과 검색 스텁
│   │   └── scanner/       # Semgrep, CodeQL, 인프라 분석 Runner 스텁
│   └── main.py            # FastAPI 애플리케이션 진입점
├── .github/workflows/     # CI 및 Docker 이미지 배포 워크플로
├── .env.example           # 로컬 환경 변수 예시
├── Dockerfile             # API·Worker 공용 컨테이너 이미지 정의
└── requirements.txt       # Python 의존성 목록
```

<br />

## Team

<div align="center">
<table>
  <tr>
    <td align="center" width="220">
      <a href="https://github.com/boogiewooki02">
        <img src="https://github.com/boogiewooki02.png" width="100" alt="김동욱" />
        <br />
        <strong>김동욱</strong>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://github.com/dldusgh318">
        <img src="https://github.com/dldusgh318.png" width="100" alt="이연호" />
        <br />
        <strong>이연호</strong>
      </a>
    </td>
  </tr>
</table>
</div>

<br />

<div align="center">

### 더 안전한 코드를 위한 가장 명확한 원인과 해답, SeCause

[Website](https://www.secause.site) · [Organization](https://github.com/SeCause) · [Frontend](https://github.com/SeCause/SeCause-FE) · [Backend](https://github.com/SeCause/SeCause-BE) · [Analysis](https://github.com/SeCause/SeCause-Analysis)

</div>
