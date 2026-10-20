"""
Patch Differ
- 구버전(취약) 펌웨어 vs 신버전(패치된) 펌웨어를 비교
- 변경된 파일/함수/문자열을 추출해서 investigator에 패치 포커스 컨텍스트 제공
"""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


class PatchDiffer:
    def __init__(self, work_dir: str | None = None):
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="fbi_patch_")

    def diff(self, old_path: str, new_path: str) -> dict:
        """두 펌웨어 이미지를 비교하고 구조화된 diff 결과를 반환."""
        print(f"[PatchDiff] 비교 시작")
        print(f"[PatchDiff]  구버전(취약): {old_path}")
        print(f"[PatchDiff]  신버전(패치): {new_path}")

        result: dict = {
            "old_firmware": old_path,
            "new_firmware": new_path,
            "old_hash": _hash_file(old_path),
            "new_hash": _hash_file(new_path),
            "size_diff_bytes": Path(new_path).stat().st_size - Path(old_path).stat().st_size,
            "modified_files": [],
            "added_files": [],
            "removed_files": [],
            "new_strings": [],
            "removed_strings": [],
            "radiff2_changed_functions": [],
            "radiff2_summary": None,
            "binary_patch_blocks": [],
            "patch_focus_hint": "",
        }

        old_extract = Path(self.work_dir) / "old_extracted"
        new_extract = Path(self.work_dir) / "new_extracted"
        old_extract.mkdir(parents=True, exist_ok=True)
        new_extract.mkdir(parents=True, exist_ok=True)

        # 1. binwalk로 양쪽 추출
        print(f"[PatchDiff] binwalk 추출 중...")
        old_fs = _binwalk_extract(old_path, str(old_extract))
        new_fs = _binwalk_extract(new_path, str(new_extract))

        # 2. 파일시스템 비교
        if old_fs and new_fs:
            print(f"[PatchDiff] 파일시스템 비교 중...")
            fs_diff = _diff_filesystems(old_fs, new_fs)
            result["modified_files"] = fs_diff["modified"]
            result["added_files"] = fs_diff["added"]
            result["removed_files"] = fs_diff["removed"]
            print(f"[PatchDiff]  수정된 파일: {len(fs_diff['modified'])}개")
            print(f"[PatchDiff]  추가된 파일: {len(fs_diff['added'])}개")
            print(f"[PatchDiff]  삭제된 파일: {len(fs_diff['removed'])}개")
        else:
            print(f"[PatchDiff] 파일시스템 추출 실패 — 바이너리 직접 비교로 진행")

        # 3. strings 비교
        print(f"[PatchDiff] strings 비교 중...")
        str_diff = _diff_strings(old_path, new_path)
        result["new_strings"] = str_diff["added"][:100]
        result["removed_strings"] = str_diff["removed"][:100]
        print(f"[PatchDiff]  추가된 문자열: {len(str_diff['added'])}개")
        print(f"[PatchDiff]  삭제된 문자열: {len(str_diff['removed'])}개")

        # 4. radiff2 바이너리 함수 diff (설치된 경우)
        print(f"[PatchDiff] radiff2 함수 비교 시도 중...")
        r2_result = _radiff2(old_path, new_path)
        if r2_result:
            result["radiff2_changed_functions"] = r2_result["changed"][:50]
            result["radiff2_summary"] = r2_result["summary"]
            print(f"[PatchDiff]  변경된 함수: {len(r2_result['changed'])}개")
        else:
            print(f"[PatchDiff]  radiff2 없음 — 건너뜀")

        # 5. 바이트 레벨 패치 블록 탐지 (cmp)
        print(f"[PatchDiff] 바이트 레벨 패치 탐지 중...")
        patches = _find_patch_blocks(old_path, new_path)
        result["binary_patch_blocks"] = patches[:20]
        if patches:
            print(f"[PatchDiff]  패치 블록: {len(patches)}개 발견")

        # 6. 분석 힌트 생성
        result["patch_focus_hint"] = _build_focus_hint(result)

        print(f"[PatchDiff] 완료")
        return result


# 내부 헬퍼
def _hash_file(path: str) -> dict:
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _binwalk_extract(fw_path: str, out_dir: str) -> str | None:
    """binwalk -e로 추출하고 추출된 루트 디렉토리 경로를 반환."""
    try:
        r = subprocess.run(
            ["binwalk", "-e", "--directory", out_dir, fw_path],
            capture_output=True, text=True, timeout=120,
        )
        # binwalk는 _<filename>.extracted 폴더를 만듦
        stem = Path(fw_path).name.replace(".", "_")
        candidates = list(Path(out_dir).glob("*extracted*")) + list(Path(out_dir).glob("_*"))
        if candidates:
            return str(candidates[0])
        # 그냥 out_dir에 직접 내용이 있는 경우
        if any(Path(out_dir).iterdir()):
            return out_dir
    except Exception:
        pass
    return None


def _diff_filesystems(old_root: str, new_root: str) -> dict:
    """두 추출 디렉토리를 재귀 비교 — 수정/추가/삭제 파일 목록 반환."""
    def collect_hashes(root: str) -> dict[str, str]:
        result = {}
        root_p = Path(root)
        for p in root_p.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(root_p))
                try:
                    h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                    result[rel] = h
                except Exception:
                    result[rel] = "error"
        return result

    old_hashes = collect_hashes(old_root)
    new_hashes = collect_hashes(new_root)

    old_set, new_set = set(old_hashes), set(new_hashes)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    modified = sorted(
        f for f in old_set & new_set if old_hashes[f] != new_hashes[f]
    )
    return {"added": added, "removed": removed, "modified": modified}


def _diff_strings(old_path: str, new_path: str) -> dict:
    """strings 출력을 비교해서 추가/삭제된 문자열 반환."""
    def get_strings(path: str) -> set:
        try:
            r = subprocess.run(
                ["strings", "-n", "8", path],
                capture_output=True, text=True, timeout=30,
            )
            return set(l.strip() for l in r.stdout.splitlines() if l.strip())
        except Exception:
            return set()

    old_strs = get_strings(old_path)
    new_strs = get_strings(new_path)
    return {
        "added": sorted(new_strs - old_strs),
        "removed": sorted(old_strs - new_strs),
    }


def _radiff2(old_path: str, new_path: str) -> dict | None:
    """radiff2로 함수 레벨 변경사항 추출 (radare2 필요)."""
    try:
        r = subprocess.run(
            ["radiff2", "-C", old_path, new_path],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None

        changed = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # radiff2 -C 출력: <addr_old> <name> <similarity> <addr_new>
            parts = line.split()
            if len(parts) >= 3:
                try:
                    similarity = float(parts[2])
                except ValueError:
                    similarity = -1.0
                changed.append({
                    "addr_old": parts[0] if len(parts) > 0 else None,
                    "name": parts[1] if len(parts) > 1 else None,
                    "similarity": similarity,
                    "addr_new": parts[3] if len(parts) > 3 else None,
                    "likely_patched": similarity < 1.0,
                })

        # 유사도 낮은 순으로 정렬 (가장 많이 바뀐 함수 먼저)
        changed.sort(key=lambda x: x.get("similarity", 1.0))

        return {
            "changed": changed,
            "summary": (
                f"총 {len(changed)}개 함수 변경 감지. "
                f"유사도 0.9 미만(크게 변경): "
                f"{sum(1 for c in changed if c.get('similarity', 1) < 0.9)}개"
            ),
        }
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _find_patch_blocks(old_path: str, new_path: str, block_size: int = 64) -> list[dict]:
    """바이트 레벨로 변경된 블록 위치를 찾아 반환."""
    try:
        old_data = Path(old_path).read_bytes()
        new_data = Path(new_path).read_bytes()
    except Exception:
        return []

    min_len = min(len(old_data), len(new_data))
    patches = []
    in_patch = False
    patch_start = 0

    for i in range(0, min_len, block_size):
        old_block = old_data[i:i + block_size]
        new_block = new_data[i:i + block_size]
        if old_block != new_block:
            if not in_patch:
                in_patch = True
                patch_start = i
        else:
            if in_patch:
                in_patch = False
                patches.append({
                    "offset": f"0x{patch_start:08x}",
                    "length": i - patch_start,
                    "old_hex": old_data[patch_start:patch_start + 16].hex(),
                    "new_hex": new_data[patch_start:patch_start + 16].hex(),
                })
                if len(patches) >= 20:
                    break

    if in_patch:
        patches.append({
            "offset": f"0x{patch_start:08x}",
            "length": min_len - patch_start,
            "old_hex": old_data[patch_start:patch_start + 16].hex(),
            "new_hex": new_data[patch_start:patch_start + 16].hex(),
        })

    return patches


def _build_focus_hint(result: dict) -> str:
    """분석 힌트 문자열 생성 — 오케스트레이터 프롬프트에 포함됨."""
    hints = []

    changed = result.get("radiff2_changed_functions", [])
    critical_fns = [c for c in changed if c.get("similarity", 1) < 0.8]
    if critical_fns:
        names = [c.get("name", "?") for c in critical_fns[:5]]
        hints.append(f"크게 변경된 함수 (유사도<0.8): {', '.join(names)}")

    modified = result.get("modified_files", [])
    if modified:
        hints.append(f"수정된 파일 {len(modified)}개: {', '.join(modified[:5])}")

    rm_strs = result.get("removed_strings", [])
    interesting_rm = [s for s in rm_strs if any(
        k in s.lower() for k in ("overflow", "error", "fail", "invalid", "too", "stack", "heap", "format")
    )]
    if interesting_rm:
        hints.append(f"삭제된 오류/경고 문자열 (패치 시그니처): {interesting_rm[:5]}")

    patches = result.get("binary_patch_blocks", [])
    if patches:
        hints.append(f"바이너리 패치 블록 {len(patches)}개 발견 (첫 번째: {patches[0].get('offset')})")

    if not hints:
        hints.append("파일시스템/문자열 레벨 변경 감지 — 수정된 컴포넌트를 중심으로 분석 필요")

    return " | ".join(hints)
