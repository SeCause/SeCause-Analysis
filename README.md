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
