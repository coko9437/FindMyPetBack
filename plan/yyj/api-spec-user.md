# 회원 관리 API 명세서

## 1. 기본 정보

- **Base URL:** `/api`
- **인증 방식:** 인증이 필요한 모든 API는 HTTP Header에 다음 형식을 포함해야 합니다.
  - `Authorization: Bearer {AccessToken}`

## 2. 공통 응답 형식

### 성공 응답

```json
{
  "success": true,
  "message": "요청 처리 성공 메시지",
  "data": {
    // 요청에 따른 실제 데이터
  }
}
```

### 실패 응답

```json
{
  "success": false,
  "error": {
    "code": "에러 코드 (e.g., BAD_REQUEST)",
    "message": "에러 발생 원인 메시지"
  }
}
```

---

## 3. API 명세

### 3.1 인증 (Authentication)

#### **1) 회원가입**

- **Endpoint:** `POST /auth/signup`
- **설명:** 새로운 사용자를 등록합니다.
- **Request Body:**
  ```json
  {
    "loginId": "newuser",
    "password": "password123",
    "name": "새로운유저",
    "phoneNumber": "010-1111-2222",
    "email": "new@example.com",
    "address": "부산시 해운대구"
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "success": true,
    "message": "회원가입이 완료되었습니다.",
    "data": {
      "userId": 2,
      "loginId": "newuser",
      "name": "새로운유저",
      "phoneNumber": "010-1111-2222",
      "email": "new@example.com",
      "address": "부산시 해운대구",
      "role": "USER"
    }
  }
  ```

#### **2) 로그인**

- **Endpoint:** `POST /auth/login`
- **설명:** 아이디와 비밀번호로 사용자를 인증하고, Access/Refresh 토큰을 발급합니다.
- **Request Body:**
  ```json
  {
    "loginId": "newuser",
    "password": "password123"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "로그인 성공",
    "data": {
      "accessToken": "eyJ...",
      "refreshToken": "eyJ...",
      "user": {
        "userId": 2,
        "loginId": "newuser",
        "name": "새로운유저",
        "role": "USER"
      }
    }
  }
  ```

#### **3) Access Token 재발급**

- **Endpoint:** `POST /auth/refresh`
- **설명:** 유효한 Refresh Token으로 새로운 Access Token을 재발급받습니다.
- **Request Body:**
  ```json
  {
    "refreshToken": "eyJ..."
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "Access Token이 재발급되었습니다.",
    "data": {
      "accessToken": "eyJ..."
    }
  }
  ```

### 3.2 사용자 (User)

#### **1) 내 정보 조회**

- **Endpoint:** `GET /users/me`
- **인증:** 필요 (Bearer Token)
- **설명:** 현재 로그인된 사용자의 상세 정보를 조회합니다.
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "내 정보 조회 성공",
    "data": {
      "userId": 2,
      "loginId": "newuser",
      "name": "새로운유저",
      "phoneNumber": "010-1111-2222",
      "email": "new@example.com",
      "address": "부산시 해운대구",
      "role": "USER"
    }
  }
  ```

#### **2) 내 정보 수정**

- **Endpoint:** `PUT /users/me`
- **인증:** 필요 (Bearer Token)
- **설명:** 현재 로그인된 사용자의 정보를 수정합니다. 변경할 필드만 포함하여 요청합니다.
- **Request Body:**
  ```json
  {
    "name": "수정된이름",
    "address": "서울시 강남구",
    "passwordChange": {
      "currentPassword": "password123",
      "newPassword": "newPassword456"
    }
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "회원 정보가 수정되었습니다.",
    "data": null
  }
  ```
