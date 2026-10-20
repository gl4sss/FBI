#!/usr/bin/env python3
"""
FBI entry point — investigator/main.py로 리다이렉트합니다.
이전 명령어: python main.py firmware.bin
새 명령어:   python investigator/main.py firmware.bin  (또는 python -m investigator.main)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from investigator.main import main

if __name__ == "__main__":
    print("[FBI] investigator/main.py로 실행합니다. (이 파일은 호환성 유지용)", file=sys.stderr)
    main()
