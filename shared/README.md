# Shared

여러 단계에서 함께 쓰는 코드입니다.

- `codex_client.py`: Codex CLI 실행과 세션 ID 추출
- `validation.py`: 작업 계획 및 워커 결과 검증
- `resume.py`: 저장된 작업 결과 복원
- `prompting.py`: 펌웨어·세션 자료의 입력 경계 표시
- `logger.py`: 오케스트레이터 및 워커 대화 기록
- `session_manager.py`: 워커 작업과 Codex 세션 연결
- `mcp_manager.py`: 설정된 MCP 서버 등록

오케스트레이터의 호출은 `medium`, 분석 작업의 호출은 `high`를 기본으로 사용합니다. 호출 결과와 세션 ID는 각 단계의 로그에 저장됩니다.
