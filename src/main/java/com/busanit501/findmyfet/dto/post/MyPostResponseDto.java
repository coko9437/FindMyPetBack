package com.busanit501.findmyfet.dto.post;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.domain.post.PostType;
import com.busanit501.findmyfet.domain.post.Status;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
public class MyPostResponseDto {
    private Long postId;
    private String title;
    private PostType postType;
    private Status status;
    private LocalDateTime createdAt;
    // private int commentCount; // TODO: Comment 기능 연동 후 주석 해제

    public MyPostResponseDto(Post entity) {
        this.postId = entity.getId();
        this.title = entity.getTitle();
        this.postType = entity.getPostType();
        this.status = entity.getStatus();
        this.createdAt = entity.getCreatedAt();
        // this.commentCount = entity.getComments().size();
    }

}
