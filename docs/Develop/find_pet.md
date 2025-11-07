# 📋 '찾아줘요' 프로젝트 최종 계획서

**문서 버전: 1.0**
**작성일: 2025-08-21**

---

## 1단계: 기획 의도 및 목표

### 1.1. 기획 의도

반려동물에 대한 관심이 증가하고 관련 산업이 고도화됨에 따라, 반려동물의 개체 수 또한 급증하고 있습니다. 이와 함께 실종 및 유기동물 문제 역시 심각한 사회적 이슈로 대두되고 있습니다. 본 프로젝트는 이러한 사회 문제 해결에 기여하고자, 실종 및 유기동물에 대한 정보를 사용자들이 손쉽게 공유하고 참여할 수 있는 플랫폼을 제공하는 것을 목표로 합니다.

### 1.2. 핵심 미션 (Core Mission)

실종/유기동물 데이터를 **지도 기반으로 시각화**하고, 커뮤니티의 **제보 참여를 유도**하여 동물이 가족의 품으로 돌아가는 시간을 단축시킨다.

### 1.3. 핵심 기능 (Key Features)

- 실종 동물 등록 및 지도 표시 (찾아요)
- 보호/목격 동물 등록 및 지도 표시 (기다려요)
- 게시글 기반 댓글 제보 시스템
- 게시글 완료 및 아카이빙 처리

### 1.4. 장기적 확장 계획 (Monetization)

부수적인 수익 모델(광고, 제품 판매)은 프로젝트의 핵심 기능이 안정적으로 완성된 후, **2차 목표**로 설정하여 진행합니다.

---

## 2단계: 요구사항 명세

| ID           | 기능명           | 상세 설명                                                   | 사용자/권한      | 비고 (추가 제안)               |
| :----------- | :--------------- | :---------------------------------------------------------- | :--------------- | :----------------------------- |
| **USER-01**  | 회원가입         | 아이디, 이름, 비밀번호, 연락처 등 정보 입력                 | 누구나           |                                |
| **USER-02**  | 로그인           | 아이디와 비밀번호로 로그인                                  | 누구나           | 소셜 로그인 추가 고려          |
| **USER-03**  | 내 정보 수정     | 연락처, 비밀번호 등 개인 정보 수정                          | 일반회원, 관리자 |                                |
| **POST-01**  | 게시글 작성      | '찾아요', '기다려요' 유형 선택 후 내용 작성.                | 일반회원, 관리자 |                                |
| **POST-02**  | 게시글 목록 조회 | 3x3 카드 형태로 게시글 목록을 확인. 페이지네이션 기능 포함. | 누구나           |                                |
| **POST-03**  | 게시글 상세 조회 | 특정 게시글의 모든 정보와 댓글을 확인.                      | 누구나           |                                |
| **POST-04**  | 게시글 수정      | 본인이 작성한 게시글의 내용을 수정.                         | 일반회원, 관리자 | 관리자는 모든 글 수정 가능     |
| **POST-05**  | 게시글 삭제      | 본인이 작성한 게시글을 삭제.                                | 일반회원, 관리자 | 관리자는 모든 글 삭제 가능     |
| **POST-06**  | 찾기 완료 처리   | 본인이 작성한 게시글의 상태를 '완료'로 변경.                | 일반회원, 관리자 | `(찾아요.)` -> `(찾았어요!)`   |
| **POST-07**  | 게시글 검색      | 동물 종류, 지역 등을 기준으로 게시글을 검색.                | 누구나           | (매우 중요한 기능)             |
| **CMT-01**   | 댓글 작성        | 게시글에 이미지 포함 댓글을 작성하여 제보.                  | 일반회원, 관리자 | `찾기 완료`된 글에는 작성 불가 |
| **CMT-02**   | 댓글 수정        | 본인이 작성한 댓글을 수정.                                  | 일반회원, 관리자 |                                |
| **CMT-03**   | 댓글 삭제        | 본인이 작성한 댓글을 삭제.                                  | 일반회원, 관리자 |                                |
| **ADMIN-01** | 관리자 기능      | 모든 게시글과 댓글을 수정/삭제할 수 있는 권한.              | 관리자           |                                |

---

## 3단계: 화면 설계

### 3.1. 메인 화면 (`/`)

- **헤더:** 로고("찾아줘요"), 로그인/회원가입 버튼
- **중앙:** "가족을 찾아요" 버튼 (`/board/missing`), "주인을 기다려요" 버튼 (`/board/shelter`)

### 3.2. 게시판 화면 (`/board/{type}`)

- **상단:** 게시판 제목, 글쓰기 버튼
- **본문:** 3x3 그리드 카드 레이아웃 (썸네일, 제목, 동물 이름, 종류)
- **하단:** 페이지네이션 컴포넌트

### 3.3. 게시글 상세 화면 (`/post/{postId}`)

- **게시글 영역:** 제목, 작성자/작성일, 본문 이미지(슬라이드), 동물 정보 표, 카카오맵, (작성자용) 수정/삭제/"찾기 완료" 버튼
- **댓글 영역:** 댓글 작성 폼(이미지 첨부 포함), 댓글 목록

### 3.4. 게시글 작성/수정 화면 (`/post/new`, `/post/edit/{postId}`)

- 제목, 이미지 첨부(미리보기), 동물 정보 폼, 실종 시간, 카카오맵 위치 선택, 등록/수정 버튼

---

## 4단계: 데이터베이스 설계 (ERD)

### 4.1. 테이블 구조

- **USER:** 사용자 정보 (user_id, login_id, password, name, phone_number, email, address, role)
- **POST:** 통합 게시글 (post_id, user_id, title, content, animal 정보, 위치 정보, post_type, status, created_at)
- **COMMENT:** 통합 댓글 (comment_id, post_id, user_id, content, created_at)
- **IMAGE:** 통합 이미지 (image_id, post_id(Nullable), comment_id(Nullable), image_url)

### 4.2. ERD (Mermaid Code)

````mermaid
erDiagram
    users {
        bigint user_id PK
        varchar login_id UK
        varchar password
        varchar name
        varchar phone_number
        varchar email UK
        varchar address
        varchar role
    }
    post {
        bigint post_id PK
        bigint user_id FK
        varchar title
        text content
        varchar animal_name
        int animal_age
        varchar animal_category
        varchar animal_breed
        datetime lost_time
        decimal latitude
        decimal longitude
        varchar post_type
        varchar status
        datetime created_at
    }
    comment {
        bigint comment_id PK
        bigint post_id FK
        bigint user_id FK
        text content
        datetime created_at
    }
    image {
        bigint image_id PK
        bigint post_id FK
        bigint comment_id FK
        varchar image_url
    }
    users ||--o{ post : "writes"
    users ||--o{ comment : "writes"
    post ||--o{ comment : "contains"
    post ||--o{ image : "attaches"
    comment ||--o{ image : "attaches"


5단계: API 명세서 (v1)
Base URL: https://api.findmypet.com/v1
인증: JWT (Bearer Authentication)

## 인증 및 권한
- **인증 방식**: JWT Token (Bearer Authentication)
- **권한 레벨**:
  - `ANONYMOUS`: 비회원 (조회만 가능)
  - `USER`: 일반 회원
  - `ADMIN`: 관리자

---

## 1. 사용자 관리 (User Management)

### 1.1 회원가입
```http
POST /api/users/register
````

**Request Body:**

```json
{
  "loginId": "user123",
  "password": "password123!",
  "name": "홍길동",
  "phoneNumber": "010-1234-5678",
  "email": "user@example.com",
  "address": "서울시 강남구"
}
```

**Response (201 Created):**

```json
{
  "success": true,
  "message": "회원가입이 완료되었습니다.",
  "data": {
    "userId": 1,
    "loginId": "user123",
    "name": "홍길동"
  }
}
```

### 1.2 로그인

```http
POST /api/users/login
```

**Request Body:**

```json
{
  "loginId": "user123",
  "password": "password123!"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "로그인 성공",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "userId": 1,
      "loginId": "user123",
      "name": "홍길동",
      "role": "USER"
    }
  }
}
```

### 1.3 내 정보 조회

```http
GET /api/users/me
Authorization: Bearer {token}
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "userId": 1,
    "loginId": "user123",
    "name": "홍길동",
    "phoneNumber": "010-1234-5678",
    "email": "user@example.com",
    "address": "서울시 강남구",
    "role": "USER"
  }
}
```

### 1.4 내 정보 수정

```http
PUT /api/users/me
Authorization: Bearer {token}
```

**Request Body:**

```json
{
  "name": "홍길동",
  "phoneNumber": "010-9999-8888",
  "email": "newemail@example.com",
  "address": "서울시 서초구"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "정보가 성공적으로 수정되었습니다."
}
```

---

## 2. 게시글 관리 (Post Management)

### 2.1 게시글 목록 조회

```http
GET /api/posts
```

**Query Parameters:**

- `type`: `MISSING` | `SHELTER` (필수)
- `page`: 페이지 번호 (default: 0)
- `size`: 페이지 크기 (default: 9)
- `category`: 동물 카테고리 (선택, 예: "개", "고양이")
- `region`: 지역 (선택)
- `keyword`: 검색 키워드 (선택)

**Example Request:**

```http
GET /api/posts?type=MISSING&page=0&size=9&category=개
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "posts": [
      {
        "postId": 1,
        "title": "말티즈 '몽이'를 찾습니다",
        "animalName": "몽이",
        "animalCategory": "개",
        "animalBreed": "말티즈",
        "thumbnailUrl": "https://cdn.findmypet.com/images/thumb_001.jpg",
        "postType": "MISSING",
        "status": "ACTIVE",
        "createdAt": "2024-01-15T14:30:00",
        "author": {
          "userId": 1,
          "name": "홍길동"
        }
      }
    ],
    "pagination": {
      "currentPage": 0,
      "totalPages": 5,
      "totalElements": 45,
      "hasNext": true,
      "hasPrevious": false
    }
  }
}
```

### 2.2 게시글 상세 조회

```http
GET /api/posts/{postId}
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "postId": 1,
    "title": "말티즈 '몽이'를 찾습니다",
    "content": "어제 저녁 산책 중에 실종되었습니다...",
    "animalName": "몽이",
    "animalAge": 3,
    "animalCategory": "개",
    "animalBreed": "말티즈",
    "lostTime": "2024-01-14T19:00:00",
    "latitude": 37.5665,
    "longitude": 126.978,
    "postType": "MISSING",
    "status": "ACTIVE",
    "createdAt": "2024-01-15T14:30:00",
    "author": {
      "userId": 1,
      "name": "홍길동",
      "phoneNumber": "010-1234-5678"
    },
    "images": [
      {
        "imageId": 1,
        "imageUrl": "https://cdn.findmypet.com/images/001.jpg"
      },
      {
        "imageId": 2,
        "imageUrl": "https://cdn.findmypet.com/images/002.jpg"
      }
    ]
  }
}
```

### 2.3 게시글 작성

```http
POST /api/posts
Authorization: Bearer {token}
```

**Request Body (multipart/form-data):**

```
title: "말티즈 '몽이'를 찾습니다"
content: "어제 저녁 산책 중에 실종되었습니다..."
animalName: "몽이"
animalAge: 3
animalCategory: "개"
animalBreed: "말티즈"
lostTime: "2024-01-14T19:00:00"
latitude: 37.5665
longitude: 126.9780
postType: "MISSING"
images: [File, File, ...]
```

**Response (201 Created):**

```json
{
  "success": true,
  "message": "게시글이 성공적으로 등록되었습니다.",
  "data": {
    "postId": 1
  }
}
```

### 2.4 게시글 수정

```http
PUT /api/posts/{postId}
Authorization: Bearer {token}
```

**Request Body:** (게시글 작성과 동일한 형식)

**Response (200 OK):**

```json
{
  "success": true,
  "message": "게시글이 성공적으로 수정되었습니다."
}
```

### 2.5 게시글 삭제

```http
DELETE /api/posts/{postId}
Authorization: Bearer {token}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "게시글이 성공적으로 삭제되었습니다."
}
```

### 2.6 찾기 완료 처리

```http
PUT /api/posts/{postId}/complete
Authorization: Bearer {token}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "찾기 완료 처리되었습니다."
}
```

### 2.7 내가 작성한 게시글 목록

```http
GET /api/posts/my
Authorization: Bearer {token}
```

**Query Parameters:**

- `page`: 페이지 번호 (default: 0)
- `size`: 페이지 크기 (default: 10)
- `status`: `ACTIVE` | `COMPLETED` (선택)

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "posts": [
      {
        "postId": 1,
        "title": "말티즈 '몽이'를 찾습니다",
        "postType": "MISSING",
        "status": "COMPLETED",
        "createdAt": "2024-01-15T14:30:00",
        "commentCount": 5
      }
    ],
    "pagination": {
      "currentPage": 0,
      "totalPages": 2,
      "totalElements": 15
    }
  }
}
```

---

## 3. 댓글 관리 (Comment Management)

### 3.1 댓글 목록 조회

```http
GET /api/posts/{postId}/comments
```

**Query Parameters:**

- `page`: 페이지 번호 (default: 0)
- `size`: 페이지 크기 (default: 20)

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "comments": [
      {
        "commentId": 1,
        "content": "비슷한 아이를 봤어요! 사진 첨부합니다.",
        "createdAt": "2024-01-15T15:30:00",
        "author": {
          "userId": 2,
          "name": "김영희"
        },
        "images": [
          {
            "imageId": 10,
            "imageUrl": "https://cdn.findmypet.com/images/comment_001.jpg"
          }
        ]
      }
    ],
    "pagination": {
      "currentPage": 0,
      "totalPages": 1,
      "totalElements": 3
    }
  }
}
```

### 3.2 댓글 작성

```http
POST /api/posts/{postId}/comments
Authorization: Bearer {token}
```

**Request Body (multipart/form-data):**

```
content: "비슷한 아이를 봤어요! 사진 첨부합니다."
images: [File, File, ...]
```

**Response (201 Created):**

```json
{
  "success": true,
  "message": "댓글이 성공적으로 등록되었습니다.",
  "data": {
    "commentId": 1
  }
}
```

### 3.3 댓글 수정

```http
PUT /api/comments/{commentId}
Authorization: Bearer {token}
```

**Request Body (multipart/form-data):**

```
content: "수정된 댓글 내용입니다."
images: [File, File, ...]
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "댓글이 성공적으로 수정되었습니다."
}
```

### 3.4 댓글 삭제

```http
DELETE /api/comments/{commentId}
Authorization: Bearer {token}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "댓글이 성공적으로 삭제되었습니다."
}
```

---

## 4. 이미지 관리 (Image Management)

### 4.1 이미지 업로드

```http
POST /api/images/upload
Authorization: Bearer {token}
```

**Request Body (multipart/form-data):**

```
images: [File, File, ...]
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "imageUrls": [
      "https://cdn.findmypet.com/images/temp_001.jpg",
      "https://cdn.findmypet.com/images/temp_002.jpg"
    ]
  }
}
```

---

## 5. 검색 및 필터링 (Search & Filter)

### 5.1 동물 카테고리 목록

```http
GET /api/categories
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "categories": [
      {
        "category": "개",
        "breeds": ["말티즈", "푸들", "골든리트리버", "진돗개"]
      },
      {
        "category": "고양이",
        "breeds": ["코리안숏헤어", "페르시안", "러시안블루", "샴"]
      }
    ]
  }
}
```

### 5.2 지역 목록

```http
GET /api/regions
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "regions": [
      "서울시",
      "부산시",
      "대구시",
      "인천시",
      "광주시",
      "대전시",
      "울산시",
      "경기도",
      "강원도"
    ]
  }
}
```

---

## 6. 관리자 기능 (Admin)

### 6.1 모든 게시글 관리

```http
GET /api/admin/posts
Authorization: Bearer {admin_token}
```

**Query Parameters:**

- `page`: 페이지 번호 (default: 0)
- `size`: 페이지 크기 (default: 20)
- `status`: `ACTIVE` | `COMPLETED` (선택)
- `keyword`: 검색 키워드 (선택)

### 6.2 게시글 강제 삭제

```http
DELETE /api/admin/posts/{postId}
Authorization: Bearer {admin_token}
```

### 6.3 댓글 강제 삭제

```http
DELETE /api/admin/comments/{commentId}
Authorization: Bearer {admin_token}
```

### 6.4 사용자 목록 조회

```http
GET /api/admin/users
Authorization: Bearer {admin_token}
```

---

## 7. 통계 및 모니터링

### 7.1 대시보드 통계

```http
GET /api/stats/dashboard
Authorization: Bearer {token}
```

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "totalPosts": 1234,
    "missingPosts": 678,
    "shelterPosts": 556,
    "completedPosts": 890,
    "todayPosts": 15,
    "recentCompletions": [
      {
        "postId": 123,
        "title": "말티즈 '몽이'를 찾습니다",
        "completedAt": "2024-01-15T16:00:00"
      }
    ]
  }
}
```

---

## 8. 공통 에러 응답

### 8.1 인증 실패 (401 Unauthorized)

```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "인증이 필요합니다."
  }
}
```

### 8.2 권한 부족 (403 Forbidden)

```json
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "접근 권한이 없습니다."
  }
}
```

### 8.3 리소스 없음 (404 Not Found)

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "요청한 리소스를 찾을 수 없습니다."
  }
}
```

### 8.4 유효성 검사 실패 (400 Bad Request)

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "입력값이 올바르지 않습니다.",
    "details": [
      {
        "field": "title",
        "message": "제목은 필수 입력사항입니다."
      },
      {
        "field": "phoneNumber",
        "message": "올바른 전화번호 형식이 아닙니다."
      }
    ]
  }
}
```

### 8.5 서버 에러 (500 Internal Server Error)

```json
{
  "success": false,
  "error": {
    "code": "INTERNAL_SERVER_ERROR",
    "message": "서버 내부 오류가 발생했습니다."
  }
}
```

---

## 9. 개발 참고사항

### 9.1 페이지네이션 표준

- 모든 목록 조회 API는 페이지네이션을 지원합니다.
- `page`는 0부터 시작합니다.
- 기본 페이지 크기는 용도에 따라 다릅니다 (게시글: 9개, 댓글: 20개)

### 9.2 이미지 처리

- 이미지는 AWS S3 또는 클라우드 스토리지에 저장됩니다.
- 썸네일은 자동으로 생성되어 성능을 최적화합니다.
- 지원 형식: JPG, PNG (최대 5MB)

### 9.3 보안 고려사항

- 모든 비밀번호는 bcrypt로 해시화하여 저장합니다.
- JWT 토큰의 만료시간: Access Token(2시간), Refresh Token(2주)
- API Rate Limiting: 사용자당 분당 100회 요청 제한

### 9.4 데이터베이스 인덱스 권장사항

```sql
-- 게시글 검색 성능 최적화
CREATE INDEX idx_post_type_status ON POST(post_type, status);
CREATE INDEX idx_post_category ON POST(animal_category);
CREATE INDEX idx_post_created_at ON POST(created_at DESC);

-- 댓글 조회 성능 최적화
CREATE INDEX idx_comment_post_id ON COMMENT(post_id);
```
