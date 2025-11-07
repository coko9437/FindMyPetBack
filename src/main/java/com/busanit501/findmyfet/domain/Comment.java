package com.busanit501.findmyfet.domain;
import jakarta.persistence.*;
import com.busanit501.findmyfet.domain.post.Post;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "comment")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Comment {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long commentId; // 댓글 고유 ID

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "post_id", nullable = false)
    @com.fasterxml.jackson.annotation.JsonIgnore
    private Post post; // 댓글이 속한 게시글

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user; // 댓글 작성자

    @Column(nullable = false, length = 500)
    private String content; // 댓글 내용

    @Column(length = 255)
    private String imageUrl; // 이미지 첨부 URL (선택 사항)

    private LocalDateTime createdAt; // 작성 시간

    private LocalDateTime updatedAt; // 수정 시간

    // ✅✅✅ 내용과 이미지 URL을 수정하는 메서드 추가 ✅✅✅
    public void updateContent(String content, String imageUrl) {
        this.content = content;
        this.imageUrl = imageUrl;
    }

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}