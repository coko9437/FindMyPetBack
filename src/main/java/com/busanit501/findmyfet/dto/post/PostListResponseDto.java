package com.busanit501.findmyfet.dto.post;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.domain.post.PostType;
import com.busanit501.findmyfet.domain.post.Status;
import com.busanit501.findmyfet.dto.user.AuthorDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
public class PostListResponseDto {
    private Long postId;
    private String title;
    private String animalName;
    private String thumbnailUrl; // 디폴트값 null;
    private PostType postType; // Post 엔티티와 타입을 맞춤
    private Status status;     // Post 엔티티와 타입을 맞춤
    private LocalDateTime createdAt; // 추가

    private AuthorDto author; // AuthorDto 필드 추가


}