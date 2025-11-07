### 유영준님을 위한 회원관리 기능 개발 계획 (실력 향상 로드맵)

이 로드맵은 4개월차 학습자이신 유영준님이 Spring Boot와 JPA, Spring Security, JWT를 깊이 있게 이해하며 실무적인 개발 역량을 키울 수 있도록 설계되었습니다.

---

#### **Phase 1: 기본기 다지기 (DB, Entity, DTO)**

*   **목표:** 데이터베이스 설계를 코드로 옮기고, 각 계층 간 데이터 전달의 기본을 익힙니다.
*   **주요 개념:** JPA Entity, DTO 패턴, `BaseEntity`의 역할

1.  **`USER` 테이블 설계 검토 및 `BaseEntity` 이해**
    *   `설계 문서`의 `USER` 테이블 스키마를 다시 한번 확인합니다.
    *   `domain/BaseEntity.java` 코드를 분석하며 `created_at`, `updated_at`을 자동 관리하는 JPA Auditing 기능을 학습합니다.

2.  **`User` Entity 클래스 생성 (`domain` 패키지)**
    *   `USER` 테이블과 매핑되는 `User` 클래스를 만듭니다.
    *   `@Entity`, `@Id`, `@GeneratedValue`, `@Column` 등 JPA 어노테이션의 의미를 학습하며 적용합니다.
    *   `Role`은 `EnumType.STRING`을 사용하여 Enum으로 관리하는 것이 안전합니다.

3.  **`UserDTO` 클래스 생성 (`dto` 패키지)**
    *   API 요청/응답에 사용할 DTO(Data Transfer Object)를 만듭니다.
    *   **학습 포인트:** 왜 Entity를 직접 API에 노출하지 않고 DTO를 사용하는지 이해합니다. (계층 분리, 보안, 필요한 데이터만 노출)
    *   예: `UserSignupRequestDTO`, `UserLoginRequestDTO`, `UserInfoResponseDTO` 등

---

#### **Phase 2: 핵심 API 구현 (보안 제외)**

*   **목표:** Spring Boot의 3-Layer Architecture(Controller-Service-Repository) 흐름을 이해하고, 기본적인 회원가입 API를 완성합니다.
*   **주요 개념:** `RestController`, `Service`, `Repository`, `Autowired` (DI)

1.  **`UserRepository` 인터페이스 생성 (`repository` 패키지)**
    *   `JpaRepository<User, Long>`를 상속받는 인터페이스를 만듭니다.
    *   **학습 포인트:** `JpaRepository`가 제공하는 `save()`, `findById()`, `findAll()` 등 기본 CRUD 메서드의 원리를 이해합니다.
    *   `findByLoginId`와 같이 직접 쿼리 메서드를 정의해봅니다.

2.  **`UserService` 클래스 생성 (`service` 패키지)**
    *   회원가입, 로그인 등 실제 비즈니스 로직을 처리하는 클래스입니다.
    *   `@Service`, `@Transactional` 어노테이션의 역할을 학습합니다.

3.  **`UserController` 클래스 생성 (`controller` 패키지)**
    *   HTTP 요청을 받는 API 엔드포인트를 정의합니다.
    *   `@RestController`, `@RequestMapping`, `@PostMapping`, `@RequestBody` 어노테이션을 사용합니다.

4.  **회원가입 API 구현 및 테스트**
    *   **흐름:** Controller (`/api/auth/signup`) → Service (비밀번호 암호화 전, DTO→Entity 변환) → Repository (`save`)
    *   Postman 또는 Swagger를 사용하여 API가 정상적으로 동작하는지 테스트하고, DB에 데이터가 저장되는지 확인합니다.

---

#### **Phase 3: Spring Security & JWT 적용**

*   **목표:** Spring Security를 이용해 인증/인가의 기본을 구축하고, JWT를 통해 상태 없는(Stateless) 인증 시스템을 구현합니다. 이 파트가 가장 중요하고 어렵지만, 실력 향상에 핵심적입니다.
*   **주요 개념:** `Filter`, `Authentication`, `Authorization`, `PasswordEncoder`, JWT (Header, Payload, Signature)

1.  **Spring Security 의존성 추가 및 기본 설정 (`config` 패키지)**
    *   `build.gradle`에 Spring Security 의존성을 추가합니다.
    *   `SecurityConfig` 클래스를 만들어 기본적인 설정을 구성합니다. (e.g., 특정 URL은 허용, 나머지는 인증 필요)

2.  **비밀번호 암호화 적용**
    *   `SecurityConfig`에 `BCryptPasswordEncoder`를 Bean으로 등록합니다.
    *   `UserService`의 회원가입 로직에 비밀번호를 암호화하여 저장하도록 수정합니다.

3.  **JWT 유틸리티 클래스 생성 (`util` 또는 `security` 패키지)**
    *   JWT 토큰을 생성하고, 유효성을 검증하고, 토큰에서 정보를 추출하는 기능을 담은 `JwtUtil` 클래스를 만듭니다.

4.  **로그인 API 구현 및 JWT 발급**
    *   **흐름:** Controller (`/api/auth/login`) → Service (ID/PW 검증) → 성공 시 `JwtUtil`을 통해 Access Token 발급 → DTO에 담아 클라이언트에 반환

5.  **JWT 인증 필터 구현**
    *   클라이언트가 요청 헤더에 보낸 JWT 토큰을 검증하고, 유효하다면 Spring Security 컨텍스트에 인증 정보를 등록하는 `JwtAuthenticationFilter`를 만듭니다.
    *   `SecurityConfig`에 이 필터를 등록하여 매 요청마다 동작하도록 설정합니다.

---

#### **Phase 4: API 기능 완성 및 예외 처리**

*   **목표:** 인증이 필요한 API를 구현하고, 애플리케이션 전반의 예외를 통일된 형식으로 처리합니다.
*   **주요 개념:** `@AuthenticationPrincipal`, `ExceptionHandler`

1.  **인증된 사용자 정보 조회/수정 API 구현**
    *   `@AuthenticationPrincipal` 어노테이션을 사용하여 현재 로그인된 사용자의 정보를 가져오는 방법을 학습합니다.
    *   `/api/users/me` (내 정보 조회), `/api/users/me` (내 정보 수정) API를 구현합니다.

2.  **전역 예외 처리 (Global Exception Handling)**
    *   `@RestControllerAdvice`와 `@ExceptionHandler`를 사용하여 `CustomException`을 만들고, API 실패 시 `설계 문서`에 정의된 공통 응답 래퍼 형식(`{ "success": false, "error": ... }`)으로 응답하도록 구현합니다.

---

#### **Phase 5: UI 연동 및 최종 테스트 (선택)**

*   **목표:** 프론트엔드 팀원과 협업하여 실제 UI와 API를 연동하고 문제점을 해결합니다.
*   **주요 개념:** CORS

1.  **회원관리 UI 연동**
    *   프론트엔드에서 개발한 회원가입, 로그인 페이지와 API를 연동합니다.
    *   CORS(Cross-Origin Resource Sharing) 문제를 해결하는 방법을 학습하고 `SecurityConfig`에 적용합니다.
