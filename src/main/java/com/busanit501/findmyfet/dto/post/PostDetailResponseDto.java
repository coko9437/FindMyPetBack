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
import java.util.List;
import java.util.stream.Collectors;

// 상세 조회 DTO
@Getter
@Setter
@NoArgsConstructor
public class PostDetailResponseDto {

    private Long postId;
    private String title;
    private String content;
    private String animalName;
    private int animalAge;
    private String animalCategory;
    private String animalBreed;
    private LocalDateTime lostTime;

    private double latitude;
    private double longitude;

    private String gender; // <<<<<<<<<<<< 추가 (프론트에 전달할 때는 문자열로)

    private String location; // 잃어버린장소 추가 250825

    private PostType postType; // Post 엔티티와 타입을 맞춤
    private Status status;     // Post 엔티티와 타입을 맞춤

    private LocalDateTime createdAt;
    private AuthorDto author; // TODO: User 기능 연동 후 추가
    private List<String> imageUrls; // 이미지 URL 목록
    private List<com.busanit501.findmyfet.dto.CommentDTO> comments; // 댓글 목록

}
