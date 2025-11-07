## 2025년 8월 26일 작업 요약

### 오늘 작업 내용:

1.  **이메일 중복 확인 기능 추가**:
    *   `UserRepository.java`에 `findByEmail` 메서드 추가.
    *   `UserService.java`의 `signup` 메서드에 이메일 중복 확인 로직 추가.
2.  **컴파일 오류 및 빈 충돌 해결**:
    *   `UserAuthorDto.java`의 `getUserid()` 오타를 `getUserId()`로 수정.
    *   `GlobalExceptionHandler` 중복 문제 해결: `controller` 패키지의 파일을 삭제하고 `exception` 패키지의 파일을 `@RestControllerAdvice`로 수정 및 `IllegalArgumentException` 처리 방식 통일.
    *   `PostRepository` 중복 문제 해결: `repository` 패키지의 파일을 삭제하고 `repository.post` 패키지의 파일을 사용하도록 관련 코드(`CommentService.java`, `PostServiceImpl.java`) 수정.
    *   `UserRepository` 중복 문제 해결: `repository.user` 패키지의 파일을 삭제하고 `repository` 패키지의 파일을 사용하도록 관련 코드(`PostServiceImpl.java`) 수정.
    *   `CommentService.java` 및 `Comment.java`의 `Post` 엔티티 타입 불일치 해결: `domain.post.Post`를 사용하도록 임포트 및 코드 수정.
    *   `CommentServiceTests.java`의 `Post` 엔티티 관련 테스트 코드 수정: `mockPost` 초기화 및 메서드 호출 방식 변경.
    *   `CommentRepository.java`의 `findByPostPostId` 메서드명을 `findByPost_Id`로 수정하고 `CommentService.java`에서 해당 호출 업데이트.
3.  **관리자 기능 구현 시작**:
    *   `AdminController.java` 파일 생성 및 기본 구조 작성.
    *   `AdminService.java` 파일 생성 및 기본 구조 작성.
    *   `AdminController.java` 및 `AdminService.java`의 초기 컴파일 오류(임포트 문제) 일부 해결.
4.  **CORS 및 인증 문제 해결**:
    *   `SecurityConfig.java`에서 `/auth/**` 경로를 `web.ignoring()`에서 `authorizeHttpRequests().permitAll()`로 변경하여 CORS 문제가 해결되도록 수정.

### 현재 진행 중인 작업:

*   **관리자 기능 구현**: `AdminController` 및 `AdminService`의 컴파일 오류를 완전히 해결하고, 각 관리자 기능(게시글/댓글 관리, 사용자 목록 조회)의 비즈니스 로직을 구현하는 중입니다. 특히 `AdminController`의 `CommonResponse.of()` 호출 관련 컴파일 오류를 해결해야 합니다.

### 앞으로 해야 할 작업:

1.  **관리자 기능 구현 완료**:
    *   `AdminController.java` 및 `AdminService.java`의 모든 컴파일 오류 해결.
    *   각 관리자 기능의 비즈니스 로직 구현 (게시글/댓글 강제 삭제 시 이미지 파일 처리 등 `TODO` 주석 처리된 부분).
    *   필요한 DTO (`UserAdminResponseDTO` 등) 정의.
2.  **Principal 타입 통일 (보류 중)**:
    *   현재 `JwtAuthenticationFilter`는 `Long userId`를 Principal로 저장하고, `CommentController`는 `String loginId`를 기대하며, `PostController`는 `Long userId`를 사용하려 합니다. 이 불일치를 `Long userId`로 통일하는 작업이 필요합니다. (사용자 요청에 따라 현재 보류 중)
3.  **기존 테스트 실패 해결**:
    *   `FindPetPostControllerTest` (8개 실패) 및 `FindPetPostRepositoryTest` (17개 실패)의 런타임 오류 해결. 이 테스트들은 제가 작업한 내용과 직접적인 관련이 적지만, 애플리케이션의 전반적인 안정성을 위해 해결이 필요합니다.
