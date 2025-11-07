package com.busanit501.findmyfet.dto.post;

import com.busanit501.findmyfet.domain.post.AnimalGender;
import com.busanit501.findmyfet.domain.post.PostType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class PostUpdateRequestDto {
    private String title;
    private String content;
    private String animalName;
    private int animalAge;
    private String animalCategory;
    private String animalBreed;
    private LocalDateTime lostTime;

    private double latitude;
    private double longitude;

    private AnimalGender gender; // <<<<<<<<<<<< 추가 (Enum 타입 사용)

    private String location; // <<<<<<<<<<<< 추가 250825

    private PostType postType;

    // 추가: 수정 시 삭제할 기존 이미지의 ID 목록
    private List<Long> deletedImageIds;
        // 기존 이미지 중 x 버튼을 눌러 삭제한 이미지"들의 ID를 보내주는 방식으로 구현
}

