# Investigator

펌웨어의 형식과 문자열을 수집하고, 선택적으로 이전 버전과 패치 버전을 비교합니다. Codex 오케스트레이터가 분석 작업을 나누고 워커 결과를 모아 다음 작업을 결정합니다.

```bash
python3 investigator/main.py path/to/firmware.bin
python3 investigator/main.py path/to/old.bin --patched path/to/new.bin
python3 investigator/main.py path/to/firmware.bin --resume path/to/session
```

기본 모델과 병렬 작업 수는 `settings.json`에서 설정합니다. 오케스트레이터는 `medium`, 분석 워커는 `high` 추론 수준을 기본으로 사용합니다. 로그는 `sessions/investigator/`에 저장됩니다.

`main.py`는 실행 흐름, `orchestrator.py`는 작업 계획, `worker.py`는 개별 Codex 분석을 담당합니다. `firmware_utils.py`는 바이너리 기본 정보를 수집하고 `patch_differ.py`는 두 펌웨어의 차이를 계산합니다.
