# 실종/유기동물 찾기 서비스 API 명세서

## 프로젝트 개요
- **프로젝트명**: 찾아줘요 (Pet Finder Service)
- **핵심 미션**: 실종/유기동물 데이터를 지도 기반으로 시각화하고, 커뮤니티의 제보 참여를 유도하여 동물이 가족의 품으로 돌아가는 시간을 단축시킨다.
- **Base URL**: `https://api.findmypet.com`
- **API Version**: v1

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
```

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
    "longitude": 126.9780,
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

이 API 명세서를 바탕으로 프론트엔드와 백엔드 팀이 병렬로 개발을 진행할 수 있습니다.