# SeCause-Analysis

## 🚀 로컬 개발 시작

### 1. 저장소 클론
```bash
git clone https://github.com/SeCause/SeCause-Analysis.git
cd SeCause-Analysis
```

### 2. 가상환경 생성 및 활성화
```bash
# macOS / Linux
python -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Windows CMD
python -m venv venv
venv\Scripts\activate.bat

# Windows Git Bash / WSL
python -m venv venv
source venv/Scripts/activate
```

### 3. 패키지 설치
```bash
pip install -r requirements.txt
```

### 4. 환경변수 설정
```bash
cp .env.example .env
```

`.env.example`에 있는 키를 기준으로 `.env` 값을 채워주세요.

| 키 | 필수 | 예시 | 설명 |
| --- | --- | --- | --- |
| `DATABASE_URL` | 예 | `postgresql+asyncpg://user:password@localhost:5432/secause` | PostgreSQL 비동기 연결 문자열 |
| `CLAUDE_API_KEY` | 예 | `sk-ant-...` | Claude API 인증 키 |
| `REDIS_URL` | 아니오 | `redis://localhost:6379/0` | 분석 작업 큐 Redis 연결 문자열 |
| `ANALYSIS_QUEUE_NAME` | 아니오 | `analysis` | RQ 분석 작업 큐 이름 |
| `HOST` | 아니오 | `0.0.0.0` | 서버 바인딩 호스트 |
| `PORT` | 아니오 | `8001` | 서버 포트 |
| `DEBUG` | 아니오 | `false` | 개발용 디버그/리로드 여부 |

### 5. 서버 실행
```bash
python -m uvicorn app.main:app --reload --port 8001
```

### 6. 확인
- API 문서: http://localhost:8001/docs
- 헬스 체크: http://localhost:8001/health

## Docker 배포 구성

### 로컬 Docker 실행
```bash
docker compose up --build -d
```

기본 compose는 다음 컨테이너를 함께 실행합니다.

| 서비스 | 역할 |
| --- | --- |
| `analysis-api` | FastAPI 서버 (`/health`, `/api/internal/analyze`) |
| `analysis-worker` | Redis Queue 작업 처리 |
| `analysis-redis` | 분석 작업 큐 |

### 서버 ENV
운영 서버에서는 `/etc/secause/analysis.env` 파일을 만들고 아래 값을 채워주세요.

```dotenv
DATABASE_URL=postgresql+asyncpg://user:password@db-host:5432/secause
CLAUDE_API_KEY=...
ANALYSIS_QUEUE_NAME=analysis
DEBUG=false
```

`REDIS_URL`, `HOST`, `PORT`는 compose에서 주입하므로 보통 운영 env 파일에 넣지 않아도 됩니다. PostgreSQL이 같은 compose 네트워크에 있다면 `DATABASE_URL`의 host는 `localhost`가 아니라 해당 DB 서비스명이어야 합니다.

### CI/CD Secrets
GitHub Actions 배포에는 아래 secrets가 필요합니다.

| Secret | 설명 |
| --- | --- |
| `DOCKER_USERNAME` | Docker Hub 사용자명 |
| `DOCKER_PASSWORD` | Docker Hub 비밀번호 또는 토큰 |
| `ANALYSIS_DOCKER_REPO` | Analysis 이미지 저장소 예: `org/secause-analysis` |
| `SECAUSE_DOCKER_REPO` | 기존 Spring 서버 이미지 저장소 예: `org/secause` |
| `EC2_HOST` | 배포 서버 주소 |
| `EC2_USERNAME` | SSH 사용자명 |
| `EC2_SSH_KEY` | SSH private key |

### nginx 도메인 분리
`deploy/nginx/secause-analysis.conf.example`의 `server_name`을 실제 분석 서버 도메인으로 바꾸고 nginx 설정에 반영하면 됩니다.

```nginx
server_name analysis.example.com;
proxy_pass http://analysis-api:8001;
```

nginx 컨테이너가 compose 안에서 실행 중이라면 `secause` 네트워크에 같이 붙어 있어야 `analysis-api` 서비스명을 해석할 수 있습니다. nginx가 호스트에 직접 설치되어 있다면 compose에서 `analysis-api`의 `ports`를 열고 `proxy_pass http://127.0.0.1:8001;` 형태로 연결하세요.
