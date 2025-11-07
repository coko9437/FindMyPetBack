
# 유기/실종동물 지도 커뮤니티 서비스 설계 문서 (Refined)

아래 문서는 제안해주신 내용을 바탕으로, 팀이 바로 병렬 개발을 시작할 수 있도록 기획→요구사항→화면→DB/ERD→API까지 일관된 설계로 정제한 버전입니다. 실무 기준의 엔드투엔드 흐름과 세부 설계 포인트(권한, 상태, 페이징, 에러 규격, 보안 포함)를 포함했습니다.

***

## 1. 기획 의도 및 목표 구체화

- 핵심 미션: 실종/유기동물 데이터를 지도 기반으로 시각화하고, 커뮤니티 제보 참여를 활성화하여 동물이 가족의 품으로 돌아가는 시간을 단축한다.
- 핵심 가치
    - 빠른 확인: 지도 중심 UI로 시간·장소 정보를 즉시 파악
    - 신뢰 확보: 게시글 상태 관리(Active/Completed), 아카이빙으로 이력 투명성 제공
    - 참여 유도: 이미지 포함 댓글 제보, 손쉬운 등록·검색
- 범위(초기 릴리스, MVP)
    - MISSING/ SHELTER 타입 게시글 등록·조회·검색
    - 댓글 제보(이미지 포함), 상태 변경(완료)
    - 기본 권한/인증, 지도 표시(카카오맵)
- 확장(Phase 2, Monetization)
    - 광고/굿즈 등 부수 수익화는 핵심 기능 안정화 이후 진행
    - 이후 후보: 푸시 알림, 지역별 구독, 실시간 제보, 보상 포인트, 외부 보호소 API 연동

***

## 2. 요구사항 정의 (Refined)

### 2.1 기능 요구사항 명세서

| ID | 기능명 | 상세 설명 | 사용자/권한 | 비고 |
| :-- | :-- | :-- | :-- | :-- |
| USER-01 | 회원가입 | 아이디, 이름, 비밀번호, 연락처 등 입력 | 누구나 | 이메일/휴대폰 중복 검사 |
| USER-02 | 로그인 | 아이디/비밀번호 로그인 | 누구나 | 소셜 로그인 고려(Phase 2) |
| USER-03 | 내 정보 수정 | 연락처, 비밀번호 수정 | 일반회원, 관리자 | 비밀번호 변경 시 재인증 |
| POST-01 | 게시글 작성 | ‘찾아요(MISSING)’, ‘기다려요(SHELTER)’ 선택, 제목/이미지/동물정보/위치 | 일반회원, 관리자 | 다중 이미지 업로드 |
| POST-02 | 게시글 목록 조회 | 3x3 카드 그리드, 페이지네이션 | 누구나 | 정렬/필터: 최신, 거리, 상태 |
| POST-03 | 게시글 상세 조회 | 본문, 이미지 슬라이드, 동물정보 표, 지도, 댓글 | 누구나 | 작성자/작성일, 상태 표시 |
| POST-04 | 게시글 수정 | 본인 글 수정 | 일반회원, 관리자 | 관리자는 모든 글 수정 가능 |
| POST-05 | 게시글 삭제 | 본인 글 삭제 | 일반회원, 관리자 | 관리자는 모든 글 삭제 가능 |
| POST-06 | 찾기 완료 처리 | 상태를 Completed(찾았어요!)로 변경 | 일반회원, 관리자 | 완료 후 댓글 제한 옵션 |
| POST-07 | 게시글 검색 | 동물 종류, 지역, 상태/타입 등 | 누구나 | 중요: 서버 사이드 필터/인덱스 |
| CMT-01 | 댓글 작성 | 텍스트+이미지 제보 | 일반회원, 관리자 | 완료 글에는 작성 불가(옵션) |
| CMT-02 | 댓글 수정 | 본인 댓글 수정 | 일반회원, 관리자 |  |
| CMT-03 | 댓글 삭제 | 본인 댓글 삭제 | 일반회원, 관리자 |  |
| ADMIN-01 | 관리자 기능 | 모든 글/댓글 수정·삭제 | 관리자 | 사용자 관리(Phase 2) |

### 2.2 비기능 요구사항

- 보안: 비밀번호 해시(BCrypt/Argon2), 인증(JWT), 권한(Role 기반), 업로드 파일 검사/사이즈 제한
- 성능: 목록/검색 인덱스, 이미지 썸네일, 페이지네이션(Cursor/Offset)
- 가용성: 이미지 스토리지(클라우드/스토리지 서버), 백업 정책
- 접근성: 모바일 퍼스트, 대체 텍스트, 명확한 상태 라벨
- 감사/추적: created_at/updated_at, 상태 변경 로그(Phase 2)

***

## 3. 화면 설계 (Refined)

### 3.1 메인 화면 (/)

- 헤더: 로고(“찾아줘요”), 로그인/회원가입
- 본문: CTA 버튼
    - 가족을 찾아요 → /board/missing
    - 주인을 기다려요 → /board/shelter


### 3.2 게시판 화면 (/board/{type})

- 상단: 게시판 제목, 글쓰기 버튼
- 필터/검색 바: 키워드, 동물 카테고리, 품종, 상태, 지역(반경 km), 정렬(최신/거리)
- 그리드: 3x3 카드
    - 썸네일, 제목, 동물명/종, 상태 배지, 등록일(상대시간)
- 하단: 페이지네이션


### 3.3 게시글 상세 (/post/{postId})

- 헤더: 동일
- 본문:
    - 제목 + 상태 배지(Active/Completed)
    - 작성자, 작성일(상대시간), 수정일
    - 이미지 슬라이드(여러 장)
    - 동물 정보 표: 이름, 나이, 카테고리(개/고양이), 품종, 특징
    - 사건 정보: 실종/보호 시간, 위치(주소), 카카오맵(좌표)
    - 작성자 전용: 수정, 삭제, 찾기 완료
- 댓글:
    - 작성 폼: 텍스트, 이미지 첨부(미리보기)
    - 목록: 작성자, 시간, 본문, 이미지
    - 정책: 완료 글에는 작성 금지 옵션(활성화 권장)


### 3.4 게시글 작성/수정 (/post/new, /post/edit/{postId})

- 제목
- 타입 선택: MISSING / SHELTER
- 이미지 업로드: 다중, 썸네일 미리보기, 대표 지정
- 동물 정보: 이름, 나이, 카테고리(select), 품종(select/자유입력)
- 사건 정보: 실종/발견 시간(datetime), 위치 선택(카카오맵), 좌표 저장
- 등록/수정 완료 버튼, 취소

***

## 4. DB 설계 및 ERD (Critically Refined)

### 4.1 스키마

- USER
    - user_id (PK, BIGINT, AI)
    - login_id (VARCHAR, UNIQUE)
    - password (VARCHAR, 해시 저장)
    - name (VARCHAR)
    - phone_number (VARCHAR)
    - email (VARCHAR, UNIQUE)
    - address (VARCHAR)
    - role (ENUM: USER, ADMIN)
    - created_at (DATETIME)
    - updated_at (DATETIME)
- POST
    - post_id (PK, BIGINT, AI)
    - user_id (FK → USER.user_id)
    - title (VARCHAR)
    - content (TEXT)
    - animal_name (VARCHAR)
    - animal_age (INT)
    - animal_category (VARCHAR)  // 예: "개", "고양이"
    - animal_breed (VARCHAR)     // 예: "말티즈", "샴"
    - lost_time (DATETIME)
    - latitude (DECIMAL(10,7))
    - longitude (DECIMAL(10,7))
    - post_type (ENUM: MISSING, SHELTER)
    - status (ENUM: ACTIVE, COMPLETED)
    - created_at (DATETIME)
    - updated_at (DATETIME)
    - deleted_at (DATETIME, NULL) // 소프트 삭제 권장
- COMMENT
    - comment_id (PK, BIGINT, AI)
    - post_id (FK → POST.post_id ON DELETE CASCADE)
    - user_id (FK → USER.user_id)
    - content (TEXT)
    - created_at (DATETIME)
    - updated_at (DATETIME)
    - deleted_at (DATETIME, NULL)
- IMAGE
    - image_id (PK, BIGINT, AI)
    - post_id (FK → POST.post_id, NULL)
    - comment_id (FK → COMMENT.comment_id, NULL)
    - image_url (VARCHAR)
    - is_primary (BOOLEAN, default false) // 대표 이미지
    - created_at (DATETIME)


### 4.2 인덱스/설계 팁

- POST: (post_type, status), (animal_category), (animal_breed), (created_at DESC)
- 공간 검색: latitude/longitude에 공간 인덱스(Geospatial) 고려
- COMMENT: (post_id, created_at)
- IMAGE: (post_id, is_primary)

***

## 5. API 명세서 (가장 중요)

아래는 MVP 착수용 실전 예시입니다. 실제 구현 시 Swagger로 스키마/예시 응답을 자동화하세요.

### 5.1 공통 규격

- Base URL: /api
- 인증: Bearer JWT (로그인 응답 토큰)
- 응답 래퍼(권장)
    - 성공: { "success": true, "data": ... }
    - 실패: { "success": false, "error": { "code": "ENTITY_NOT_FOUND", "message": "..." } }
- 날짜/시간: ISO 8601 (UTC 권장)
- 페이징: page(0-base), size(기본 9)
- 정렬: sort=createdAt,desc 형식


### 5.2 인증/사용자

- 회원가입
    - POST /api/auth/signup
    - Body: { loginId, password, name, phoneNumber, email, address }
    - 201 Created → { userId, name, role }
- 로그인
    - POST /api/auth/login
    - Body: { loginId, password }
    - 200 OK → { accessToken, user: { userId, name, role } }
- 내 정보 조회
    - GET /api/users/me (Auth)
    - 200 OK → { userId, loginId, name, phoneNumber, email, address, role }
- 내 정보 수정
    - PUT /api/users/me (Auth)
    - Body: { name?, phoneNumber?, email?, address?, passwordChange?: { current, new } }
    - 200 OK


### 5.3 게시글

- 게시글 생성
    - POST /api/posts (Auth)
    - Body: {
title, content,
postType: "MISSING"|"SHELTER",
animal: { name, age, category, breed },
event: { lostTime }, // 발견/실종 시간
location: { latitude, longitude },
images: [ "url1", "url2" ], primaryImageIndex?: 0
}
    - 201 Created → { postId }
- 게시글 목록 조회
    - GET /api/posts
    - Query:
        - type=MISSING|SHELTER
        - status=ACTIVE|COMPLETED (optional)
        - category, breed, q(키워드), page, size, sort
        - lat, lon, radiusKm(선택: 거리 필터)
    - 200 OK → {
content: [
{ postId, title, thumbnailUrl, animal: { name, category, breed }, status, postType, createdAt }
],
pageInfo: { page, size, totalElements, totalPages }
}
- 게시글 상세 조회
    - GET /api/posts/{postId}
    - 200 OK → {
postId, title, content, status, postType,
user: { userId, name },
animal: { name, age, category, breed },
event: { lostTime },
location: { latitude, longitude, address? },
images: [ { url, isPrimary } ],
createdAt, updatedAt
}
- 게시글 수정
    - PUT /api/posts/{postId} (Auth, 소유자/관리자)
    - Body: 생성과 동일(부분 업데이트 허용 시 PATCH 고려)
    - 200 OK
- 게시글 삭제
    - DELETE /api/posts/{postId} (Auth, 소유자/관리자)
    - 204 No Content
- 찾기 완료 처리
    - PUT /api/posts/{postId}/complete (Auth, 소유자/관리자)
    - 200 OK → { postId, status: "COMPLETED" }


### 5.4 댓글

- 댓글 생성
    - POST /api/posts/{postId}/comments (Auth)
    - Body: { content, images?: [ "url1", ... ] }
    - 정책: COMPLETED 글에는 403(옵션)
    - 201 Created → { commentId }
- 댓글 목록 조회
    - GET /api/posts/{postId}/comments
    - Query: page, size, sort=createdAt,asc
    - 200 OK → {
content: [ { commentId, user: { userId, name }, content, images: [url], createdAt } ],
pageInfo: { ... }
}
- 댓글 수정
    - PUT /api/comments/{commentId} (Auth, 소유자/관리자)
    - Body: { content, images?: [ ... ] }
    - 200 OK
- 댓글 삭제
    - DELETE /api/comments/{commentId} (Auth, 소유자/관리자)
    - 204 No Content


### 5.5 이미지 업로드

- 사전 서명 URL(권장)
    - POST /api/uploads/presigned (Auth)
    - Body: { contentType, fileName }
    - 200 OK → { uploadUrl, fileUrl }
- 업로드는 클라이언트가 uploadUrl로 직접 PUT, DB에는 fileUrl 저장

***

## 6. 권한/검증/에러 정책

- 권한
    - USER: 자신의 글/댓글만 수정·삭제, 완료 처리
    - ADMIN: 모든 글/댓글 수정·삭제 가능
- 검증
    - 필수 필드: title, postType, animal.category, location(lat/lon)
    - 이미지: 확장자/크기 제한, 안전성 검사
- 에러 코드 예시
    - AUTH_REQUIRED, ACCESS_DENIED, ENTITY_NOT_FOUND, VALIDATION_ERROR, INVALID_STATE, RATE_LIMITED

***

## 7. 검색/지도/성능 설계 팁

- 텍스트 검색: title+content LIKE 또는 전문검색(엘라스틱서치) 고려
- 지오서치: lat/lon/radiusKm로 Haversine 계산 또는 공간 인덱스
- 정렬: 최신순 기본, 거리순 옵션(지오서치 시)
- 캐시: 인기 게시글/대표 이미지 CDN 캐시

***

## 8. 개발/운영 워크플로우

- API 계약: Swagger(OpenAPI)로 스키마·예시·에러 정의
- 브랜치 전략: Git Flow, BE/FE 병렬
- 배포: Dev/Staging/Prod, 환경변수 분리
- 모니터링: 요청 로깅, 에러 트래킹(Sentry), 이미지 상태 점검 잡

***

## 9. 샘플 Swagger 스키마 조각

```yaml
paths:
  /api/posts:
    get:
      parameters:
        - in: query
          name: type
          schema: { type: string, enum: [MISSING, SHELTER] }
        - in: query
          name: status
          schema: { type: string, enum: [ACTIVE, COMPLETED] }
        - in: query
          name: page
          schema: { type: integer, default: 0 }
        - in: query
          name: size
          schema: { type: integer, default: 9 }
      responses:
        '200':
          description: OK
  /api/posts/{postId}/complete:
    put:
      security: [ { bearerAuth: [] } ]
      parameters:
        - in: path
          name: postId
          required: true
          schema: { type: integer }
      responses:
        '200':
          description: Completed
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```


***

## 10. 체크리스트

- 데이터
    - 통합 POST/IMAGE 테이블로 중복 제거
    - 상태 관리(status)로 아카이빙 명확화
- UX
    - 완료 배지·상태 전환(찾아요 → 찾았어요!)
    - 지도에서 위치/시간 맥락 바로 보이기
- 성능/운영
    - 이미지 업로더(사전 서명), 썸네일
    - 지오 인덱스, 캐시, 에러 추적
- 협업
    - Swagger 공유, 목데이터로 FE 개발 병행
    - 에러 포맷/권한 매트릭스 합의

이 문서를 팀 위키/이슈 템플릿으로 등록하고, Swagger와 Postman 컬렉션을 함께 배포하면 BE/FE/디자인이 즉시 병렬로 착수할 수 있습니다.

