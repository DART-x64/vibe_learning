# 벨소리 메이커 (Ringtone Maker) 앱 개발 플랜

음원 파일을 불러와 원하는 구간을 잘라 편집하고, 휴대폰 수신음(벨소리)으로 설정하는 안드로이드 앱.

- **타깃 기기**: 삼성 갤럭시 S24 Ultra (One UI 6.x, Android 14 / API 34 기준)
- **최소 지원**: Android 10 (API 29) — Scoped Storage 기준으로 통일

> **세부 모델 간 차이에 대하여**: S24 Ultra의 세부 모델(SM-S928N 국내용, SM-S928B 글로벌, SM-S928U 미국 등)은 통신 밴드·칩셋 구성 차이일 뿐, 앱 구현 관점에서는 **차이가 없다**. 앱 동작을 좌우하는 것은 모델명이 아니라 **Android API 레벨과 One UI 버전**이며, 모든 S24 Ultra 세부 모델은 동일한 One UI/Android를 탑재한다.

---

## 1. 기술 스택

| 영역 | 선택 | 이유 |
|---|---|---|
| 언어 | Kotlin | 안드로이드 공식 권장 언어 |
| UI | Jetpack Compose + Material 3 | 파형(waveform) 같은 커스텀 UI를 Canvas로 그리기 쉬움 |
| 아키텍처 | MVVM (ViewModel + StateFlow) | 단일 화면 흐름에 적합한 표준 구조 |
| 미디어 재생 | Media3 ExoPlayer | 미리듣기(구간 반복 재생) |
| 오디오 편집/변환 | Media3 Transformer | 트리밍·인코딩을 공식 라이브러리로 처리 (FFmpeg 없이 가능) |
| 파형 추출 | MediaCodec + MediaExtractor로 PCM 디코딩 후 진폭 샘플링 | 외부 의존성 최소화 |
| 저장 | MediaStore API (`Audio.Media`, `RELATIVE_PATH = Ringtones/`) | Scoped Storage 정책 준수 |

## 2. 핵심 기능 (MVP)

1. **음원 불러오기** — 시스템 파일 선택기(`ActivityResultContracts.OpenDocument`, `audio/*`)로 MP3·M4A·WAV·FLAC·OGG 선택. 저장소 권한 불필요.
2. **파형 표시 + 구간 선택** — 파형 위에 시작/끝 핸들 드래그, 시간 직접 입력(분:초.밀리초), 핀치 줌.
3. **미리듣기** — 선택 구간만 반복 재생, 재생 위치 커서 표시.
4. **편집 옵션** — 트리밍(필수), 페이드 인/아웃, 볼륨 게인 조절.
5. **내보내기** — AAC(M4A)로 인코딩 후 MediaStore를 통해 `Ringtones/` 폴더에 저장 (`IS_RINGTONE = 1`).
6. **벨소리 설정** — `RingtoneManager.setActualDefaultRingtoneUri(TYPE_RINGTONE)`로 기본 수신음 등록. 알림음/알람음 타입도 선택 가능하게.

## 3. 권한 및 정책 (Android 14 기준)

| 작업 | 필요 권한 | 비고 |
|---|---|---|
| 음원 파일 선택 | 없음 | SAF 사용 시 권한 불필요 |
| 편집본 저장 | 없음 | 본인 앱이 MediaStore에 새로 만드는 파일은 권한 불필요 |
| 시스템 벨소리 변경 | `WRITE_SETTINGS` (특수 권한) | 런타임 다이얼로그가 아닌 **설정 화면 이동** 필요: `Settings.ACTION_MANAGE_WRITE_SETTINGS` 인텐트로 안내 후 `Settings.System.canWrite()`로 확인 |

- `WRITE_EXTERNAL_STORAGE`는 사용하지 않음 (API 29+에서 불필요/무시됨).
- 삼성 One UI 특이사항: 벨소리 설정 직후 시스템 설정 앱에 즉시 반영되는지 S24 Ultra 실기기에서 확인 필요. (One UI는 SIM 1/SIM 2 벨소리를 구분하므로, 듀얼심 사용 시 기본 API는 SIM 1에 적용된다는 점을 UI에 안내.)

## 4. 화면 구성

1. **홈 화면** — "음원 선택" 버튼, 최근 작업물(내가 만든 벨소리) 목록.
2. **편집 화면** — 파형 뷰, 시작/끝 핸들, 재생 컨트롤, 페이드/게인 옵션, "저장" 버튼.
3. **저장/설정 화면** — 파일명 입력, 타입 선택(벨소리/알림음/알람음), "벨소리로 설정" 버튼, 완료 안내.

## 5. 개발 단계

### Phase 1 — 프로젝트 골격 (1단계)
- Android Studio 프로젝트 생성 (Kotlin, Compose, minSdk 29 / targetSdk 34)
- 화면 네비게이션 골격, 테마, 의존성 세팅

### Phase 2 — 파일 선택 & 재생 (2단계)
- SAF로 음원 선택 → 메타데이터(길이, 제목) 표시
- ExoPlayer로 전체 재생/일시정지

### Phase 3 — 파형 & 구간 편집 (3단계, 핵심)
- MediaExtractor + MediaCodec로 PCM 디코딩 → 진폭 배열 추출 (백그라운드 코루틴)
- Compose Canvas로 파형 렌더링, 드래그 핸들로 구간 선택
- 선택 구간 반복 미리듣기

### Phase 4 — 내보내기 (4단계)
- Media3 Transformer로 구간 트리밍 + AAC 인코딩
- 페이드 인/아웃, 게인 적용 (AudioProcessor)
- MediaStore `Ringtones/`에 저장

### Phase 5 — 벨소리 설정 & 마무리 (5단계)
- `WRITE_SETTINGS` 권한 안내 플로우
- `RingtoneManager`로 수신음/알림음/알람음 설정
- 내가 만든 벨소리 목록·삭제, 에러 처리, S24 Ultra 실기기 테스트

## 6. 검증 체크리스트

- [ ] 다양한 포맷(MP3/M4A/WAV/FLAC/OGG) 불러오기
- [ ] 긴 음원(10분+)에서 파형 추출 성능
- [ ] 저장된 파일이 시스템 설정 > 소리 > 벨소리 목록에 노출되는지
- [ ] 벨소리 설정 후 실제 수신 시 적용 확인 (S24 Ultra 실기기)
- [ ] 권한 거부 시나리오 (WRITE_SETTINGS 거부 후 재안내)
- [ ] 듀얼심 환경에서의 동작 안내
