물론입니다. 아주 훌륭한 질문입니다. 성공적인 프로젝트는 결국 팀원 간의 원활한 협업과 소통에 달려있습니다. 다른 팀원들이 내가 만든 기능을 쉽게 이해하고 사용할 수 있도록 설명하는 것은 매우 중요한 역할입니다.

제가 **'게시글 파트 담당자'**가 되어 다른 팀원들에게 **'Post 모듈 연동 가이드'**를 설명해준다고 생각하고, 아래에 그 내용을 작성해 드리겠습니다.

---

## **Post 모듈 연동 가이드 for 지도 & 댓글 팀원**

안녕하세요, 지도 기능과 댓글 기능을 담당하시는 팀원분들!

게시글 관련 백엔드 기능 개발이 완료되어, 여러분의 기능을 연동하는 데 필요한 가이드를 공유해 드립니다. 제가 만든 `Post` 관련 기능들은 **하나의 완성된 부품**이라고 생각하시고, 이 부품을 가져다 쓰기만 하면 됩니다.

### **✅ 공통 원칙 (가장 중요!)**

1.  **서비스(Service)를 통해 소통하세요**: 여러분의 코드에서 `PostRepository`를 직접 호출하지 마세요. 게시글 정보가 필요하면 제가 만들어 둔 **`PostService`** 또는 **`PostRepository`**를 주입(`@Autowired` or `@RequiredArgsConstructor`)받아 사용해주세요.
2.  **DTO를 사용하세요**: 클라이언트(프론트엔드)와 데이터를 주고받을 때는 항상 DTO(`PostCreateRequestDto`, `PostDetailResponseDto` 등)를 사용합니다. 절대로 `Post` 엔티티를 컨트롤러에서 직접 반환하거나 파라미터로 받지 않습니다.
3.  **엔드포인트는 `PostController`를 참고하세요**: API 명세와 기능은 `PostController.java`에 모두 구현되어 있습니다. API를 어떻게 호출해야 할지 궁금하면 이 파일을 참고하시면 됩니다.

---

### **🗺️ To. 지도 기능 담당자님**

지도에 위치를 표시하고, 사용자가 선택한 위치를 게시글에 저장하는 기능을 구현하실 때 아래 내용을 참고해주세요.

#### **핵심 필드**

`Post` 엔티티에는 지도 관련 3개의 필드가 이미 준비되어 있습니다.

-   `private double latitude;` // 위도 (e.g., `35.1795543`)
-   `private double longitude;` // 경도 (e.g., `129.0756416`)
-   `private String location;` // 주소 기반 지역명 (e.g., "부산시")

#### **1. 게시글 작성/수정 시 위치 정보 저장하기**

프론트엔드에서 사용자가 Kakao Map API를 이용해 특정 위치를 클릭하면, 해당 위치의 **위도, 경도, 그리고 지역명**을 얻을 수 있습니다. 이 세 가지 데이터를 아래 DTO에 담아 API를 호출해주시면 됩니다.

-   **사용할 DTO**:
    -   `PostCreateRequestDto` (게시글 작성 시)
    -   `PostUpdateRequestDto` (게시글 수정 시)
-   **API 엔드포인트**:
    -   `POST /api/posts`
    -   `PUT /api/posts/{postId}`

**프론트엔드에서 보내야 할 JSON 데이터 예시:**

```json
{
    "title": "우리집 멍멍이를 찾아요",
    "content": "산책하다가 놓쳤어요...",
    "animalName": "해피",
    "animalCategory": "개",
    // ... 기타 동물 정보 ...

    // ▼▼▼▼▼ 지도 담당자님이 채워주셔야 할 부분 ▼▼▼▼▼
    "latitude": 37.5665,
    "longitude": 126.9780,
    "location": "서울시"
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
}
```

**결론**: 프론트엔드에서 위도, 경도, 지역명을 DTO에 담아 `PostController`로 보내주시기만 하면, 제가 만든 `PostService`가 알아서 DB에 저장합니다. **따로 백엔드 로직을 추가하실 필요가 없습니다.**

#### **2. 게시글 상세 조회 시 지도에 위치 표시하기**

-   **API 엔드포인트**: `GET /api/posts/{postId}`
-   **사용할 DTO**: `PostDetailResponseDto`

게시글 상세 조회 API를 호출하면, 응답으로 받는 `PostDetailResponseDto` 안에 `latitude`, `longitude`, `location` 필드가 이미 포함되어 있습니다.

**프론트엔드에서 받을 JSON 데이터 예시:**
```json
{
    "postId": 1,
    "title": "우리집 멍멍이를 찾아요",
    // ...
    "latitude": 37.5665,
    "longitude": 126.9780,
    "location": "서울시",
    // ...
}
```
**결론**: 이 DTO에서 위도, 경도 값을 꺼내 Kakao Map API의 `new kakao.maps.Marker()`를 사용하여 지도에 마커(핀)를 표시해주시면 됩니다.

---

### **💬 To. 댓글 기능 담당자님**

게시글에 종속되는 댓글(제보) 기능을 개발하실 때, `Post`와 `Comment`의 관계를 중심으로 생각하시면 쉽습니다.

#### **핵심 개념: `Post`는 부모, `Comment`는 자식**

`Comment` 엔티티는 어떤 게시글(`Post`)에 속해있는지를 반드시 알아야 합니다. 따라서 `Comment` 엔티티를 설계하실 때 `Post`를 참조하는 필드가 반드시 필요합니다.

**`Comment` 엔티티 설계 예시:**
```java
@Entity
public class Comment {
    // ... (comment_id, content 등) ...

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "post_id") // 외래키
    private Post post; // 이 댓글이 속한 부모 게시글

    // ... (User 정보 등) ...
}
```

#### **1. 댓글 작성하기**

-   **API 엔드포인트 (제안)**: `POST /api/posts/{postId}/comments`
-   **핵심 로직**:
    1.  댓글 서비스(`CommentService`)에서 `postId`를 파라미터로 받습니다.
    2.  제가 이미 만들어 둔 `PostRepository`를 주입받아, `postRepository.findById(postId)`를 호출하여 부모가 될 `Post` 엔티티를 먼저 조회합니다.
    3.  새로운 `Comment` 엔티티를 생성하고, 조회해온 `Post` 엔티티를 설정해줍니다 (`newComment.setPost(foundPost)`).
    4.  `CommentRepository`를 통해 새로운 댓글을 저장합니다.

#### **2. 댓글 조회하기**

-   **API 엔드포인트 (제안)**: `GET /api/posts/{postId}/comments`
-   **핵심 로직**: `CommentRepository`에 `findByPost_Id(Long postId)` 같은 메소드를 만들어 특정 게시글에 달린 댓글 목록을 조회하면 됩니다.

#### **3. 게시글 수정 시**

-   **결론: 아무것도 하실 필요 없습니다.**
-   게시글을 수정하는 `updatePost` 로직은 `Post`의 정보만 변경할 뿐, 연결된 댓글은 전혀 건드리지 않습니다. 기획서 내용과 동일하게 댓글은 변하지 않습니다.

#### **4. 게시글 삭제 시 (가장 중요!)**

-   **결론: 댓글 삭제 로직을 따로 만드실 필요가 없습니다!**

제가 `Post.java` 엔티티에 마법 같은 코드를 미리 넣어두었습니다.

**`Post.java` 내부 코드:**
```java
// Post가 삭제되면 연관된 Comment도 함께 삭제되도록 설정해야 합니다.
// @OneToMany(mappedBy = "post", cascade = CascadeType.ALL, orphanRemoval = true)
// private List<Comment> comments = new ArrayList<>();
```
현재는 주석 처리되어 있지만, `Comment` 엔티티가 만들어지면 위 코드의 주석을 풀고 `comments` 필드를 추가할 것입니다.

-   `cascade = CascadeType.ALL`: `Post`가 저장, 삭제 등 생명주기에 변경이 생길 때, `Comment`에도 똑같은 작업을 전파하라는 의미입니다. 즉, **Post가 삭제되면 Comment도 자동으로 삭제됩니다.**
-   `orphanRemoval = true`: 부모(`Post`)와의 관계가 끊어진 자식(`Comment`)은 고아로 취급하여 자동으로 DB에서 삭제하라는 의미입니다.

**최종 결론**: 제가 `Post` 엔티티에 댓글(`Comment`)과의 관계 설정을 완료하면, 여러분은 **게시글 삭제 시 댓글이 어떻게 될지 전혀 신경 쓰지 않으셔도 됩니다.** `DELETE /api/posts/{postId}` API가 호출되면 JPA가 알아서 모든 것을 처리해 줄 것입니다.

---

이 가이드가 여러분의 작업에 도움이 되기를 바랍니다. 궁금한 점이 있으면 언제든지 편하게 물어봐 주세요