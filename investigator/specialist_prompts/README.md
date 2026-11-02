# Investigator 전담 프롬프트

통합 실행은 아래 10개 프롬프트를 고정 목록으로 사용합니다. 파일 내용의 SHA256 앞 12자리가 작업의 프롬프트 버전이며, 프롬프트가 바뀌면 기존 세션에서도 새 작업으로 취급합니다. 각 프롬프트의 결과는 공통 `suspected_findings` 스키마를 따릅니다.

모든 전담 조사에서 관찰과 추론을 구분하고, 정확한 위치와 입력·사용 경로를 확인합니다. 하드코딩 값의 입력 경로는 `embedded constant`처럼 기록합니다. `disposition`은 `needs_static_research`, `static_verified`, `needs_dynamic_verification`, `insufficient_evidence` 중 하나입니다. 정적 확인은 실행 재현을 뜻하지 않습니다. 실행이 꼭 필요한 경우에만 `needs_dynamic_verification`을 선택하고, `dynamic_test_question`에 실행으로 확인할 구체적인 질문을 적으며 `unknowns`에 정적 분석으로 풀 수 없는 조건을 기록합니다. 질문이 없으면 정적 추가 조사로 남습니다. 같은 원인에서 나온 여러 영향은 별도 취약점으로 중복 등록하지 않고 `impact_tags`에 적습니다.
