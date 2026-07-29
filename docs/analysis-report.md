# WinMine 지뢰찾기 분석 보고서

## 1. 개요

`winmine.exe`를 IDA Professional 9.0으로 정적 분석하고, 실행 중 메모리 판독을 통해 지뢰 위치를 확인했다. 원본 실행 파일은 수정하지 않았으며 DLL 인젝션이나 바이너리 패치도 수행하지 않았다.

분석 결과 지뢰판은 전역 배열 `byte_1005340`에 저장된다. 각 칸은 `byte_1005340[32 * row + col]` 형식으로 접근하며 `row`와 `col`은 1부터 시작한다. 해당 바이트의 `0x80` 비트가 지뢰 여부를 나타내므로 이 비트가 없는 칸만 클릭하면 안전하게 승리할 수 있다.

## 2. 대상 정보

| 항목 | 값 |
|---|---|
| 파일명 | `winmine.exe` |
| 크기 | `119,808 bytes` |
| SHA256 | `D1A612A1791614B628A5C99F03B60FF1B979B8D1F088E99228893CB000C5DAF4` |
| MD5 | `7A5807A5144369965223903CB643C60E` |
| 형식 | PE32 Windows GUI executable |
| ImageBase | `0x01000000` |
| Entry | `0x01003E21` |
| 주요 섹션 | `.text`, `.data`, `.rsrc` |

주요 import는 `rand`, `srand`, `GetTickCount`, `SetTimer`, `InvalidateRect`, `SetCapture`, `PtInRect`와 GDI 관련 API다.

## 3. 정적 분석

### 3.1 난수 초기화

`sub_1003AB0` (`0x01003AB0`)은 `GetTickCount()`의 반환값에서 하위 16비트를 취해 `srand()`의 seed로 사용한다. 이후 새 게임을 만들 때 동일 프로세스의 `rand()`가 지뢰 좌표 생성에 사용된다.

### 3.2 난수 범위 제한

`sub_1003940` (`0x01003940`)은 `rand() % a1`을 반환하는 간단한 래퍼다. 지뢰 배치 루틴은 이 함수를 너비와 높이에 각각 적용하고 1을 더해 유효 보드 좌표를 만든다.

### 3.3 보드 초기화

`sub_1002ED5` (`0x01002ED5`)은 보드 영역을 `0x0F`로 채운 뒤 외곽을 `0x10`으로 설정한다. 이 구조 덕분에 주변 칸을 검사할 때 별도의 범위 조건을 반복하지 않아도 된다.

### 3.4 지뢰 배치

`sub_100367A` (`0x0100367A`)에서 난수 좌표를 선택한다. 이미 지뢰가 배치된 칸이면 다시 좌표를 생성하고, 비어 있는 칸이면 다음 연산으로 지뢰 비트를 설정한다.

```text
board[32 * row + col] |= 0x80
```

### 3.5 클릭 및 칸 열기

윈도우 메시지 처리 루틴 `0x01001BC9`는 클라이언트 좌표를 보드 좌표로 변환한다.

```text
col = (client_x + 4) >> 4
row = (client_y - 39) >> 4
```

반대로 셀 중심을 클릭하기 위한 좌표는 다음과 같이 정리할 수 있다.

```text
client_x = 16 * col + 4
client_y = 16 * row + 47
```

`sub_1003008` (`0x01003008`)은 주변 8칸의 `0x80` 비트를 세어 숫자를 계산하고 열린 칸에 `0x40` 비트를 설정한다.

### 3.6 승리 처리

`sub_100347C` (`0x0100347C`)는 게임 종료 상태를 갱신한다. 동적 검증에서 모든 안전 칸을 열었을 때 `face_state = 3`, `game_flags = 0x00000010`으로 전환되는 것을 확인했다.

## 4. 보드 자료구조

| 항목 | 값 |
|---|---|
| 보드 시작 주소 | `0x01005340` |
| 접근식 | `byte_1005340[32 * row + col]` |
| 행 stride | `32 bytes` |
| 너비 | `dword_1005334` |
| 높이 | `dword_1005338` |
| 현재 지뢰 수 | `dword_1005330` |
| 열린 안전 칸 수 | `dword_10057A4` |
| 전체 안전 칸 수 | `dword_10057A0` |

칸 값은 지뢰와 개방 상태를 나타내는 상위 비트, 화면 상태를 나타내는 하위 값이 결합된 구조다.

| 값 또는 마스크 | 의미 |
|---|---|
| `value & 0x80` | 지뢰 비트 |
| `value & 0x40` | 열린 칸 비트 |
| `value & 0x1F` | 화면 표시 또는 내부 상태 |
| `0x0F` | 닫힌 기본 칸 |
| `0x10` | 보드 외곽 테두리 |
| `0x0E` | 깃발 |
| `0x0D` | 물음표 |
| `0x8F` | 닫힌 지뢰 칸 |
| `0x8E` | 승리 후 깃발로 표시된 지뢰 칸 |

## 5. 메모리 판독 기반 승리 방법

1. 실행 중인 프로세스에서 너비 `0x01005334`, 높이 `0x01005338`과 보드 `0x01005340`을 읽는다.
2. 모든 유효 좌표에 대해 `cell = board[32 * row + col]`을 계산한다.
3. `cell & 0x80`이 참인 칸은 지뢰이므로 제외한다.
4. 나머지 칸에 좌표 변환식을 적용해 왼쪽 버튼 메시지를 전송한다.
5. 열린 안전 칸 수와 전체 안전 칸 수가 같아지면 승리 상태를 확인한다.

검증 스크립트는 `ReadProcessMemory`만 사용해 대상 메모리를 읽는다. 대상 메모리를 수정하거나 실행 파일을 패치하지 않는다.

## 6. 내장 XYZZY 힌트

메시지 처리 루틴에는 `X`, `Y`, `Z`, `Z`, `Y` 키 시퀀스를 검사하는 코드도 존재한다. 기능이 활성화되면 현재 마우스가 가리키는 칸의 지뢰 여부에 따라 화면 좌상단 픽셀을 검정 또는 흰색으로 바꾼다.

```text
SetPixel(
    GetDC(0),
    0,
    0,
    board[32 * row + col] < 0 ? 0 : 0xFFFFFF
)
```

signed byte가 음수라는 조건은 최상위 `0x80` 비트가 설정됐다는 뜻이므로 지뢰 판정과 일치한다.

## 7. 동적 검증

`tools/dynamic_verify_winmine.py`로 Beginner 난이도 한 판을 검증했다.

| 검증 항목 | 결과 |
|---|---|
| 보드 크기 | `9 x 9` |
| 지뢰 수 | `10` |
| 안전 칸 수 | `71` |
| 전송한 클릭 수 | `71` |
| 최종 열린 칸 | `71` |
| 최종 `face_state` | `3` |
| 최종 `game_flags` | `0x00000010` |
| 판정 | `won = true` |

초기 지뢰 좌표는 다음과 같았다.

```text
(3,4), (8,4), (4,5), (4,6), (6,6),
(5,7), (7,7), (6,8), (7,8), (8,9)
```

![자동 클릭 후 실제 승리 화면](../analysis/winmine_verification.png)

전체 실행 결과는 [`analysis/dynamic_verification.json`](../analysis/dynamic_verification.json)에 기록했다.

## 8. 결론

지뢰 배치는 난수로 이루어지지만 결과는 전역 배열 `0x01005340`에 유지된다. 각 셀의 `0x80` 비트를 확인하면 지뢰를 정확히 구분할 수 있고, 메시지 처리 루틴에서 확인한 좌표 변환식으로 안전 칸만 선택할 수 있다.

실제 검증에서는 안전 칸 71개를 모두 열어 승리 상태에 도달했다. 따라서 실행 파일을 수정하지 않고 메모리 판독만으로도 안정적으로 게임을 완료할 수 있다.

## 9. 참고 자료

- [Microsoft PE format](https://learn.microsoft.com/windows/win32/debug/pe-format)
- [Microsoft ReadProcessMemory](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
- [Microsoft GetTickCount](https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount)
- [Microsoft rand](https://learn.microsoft.com/cpp/c-runtime-library/reference/rand)
- [Microsoft srand](https://learn.microsoft.com/cpp/c-runtime-library/reference/srand)
