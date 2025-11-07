package com.busanit501.findmyfet.dto.post;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FindPetSearchCriteria {

    // 검색 조건
    private String title;        // 제목 (부분 일치)
    private String animalName;   // 동물 이름 (부분 일치)

    // 필터 조건
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime lostTimeFrom;  // 분실 시간 시작

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime lostTimeTo;    // 분실 시간 종료

    private String location;         // 분실/발견 장소
    private String animalCategory;   // 동물 카테고리 (개, 고양이 등)
    private String animalBreed;      // 품종

    // ✅ 여기 두 개를 String으로 바꿉니다 (소문자/대문자 아무거나 받아도 되게 스펙에서 변환 처리)
    private String postType;         // 예: "MISSING", "SHELTER"
    private String status;           // 예: "ACTIVE", "COMPLETED"

    // 동물 나이 범위
    private Integer animalAgeFrom;   // 최소 나이
    private Integer animalAgeTo;     // 최대 나이

    // 페이징 및 정렬
    @Min(value = 0, message = "페이지 번호는 0 이상이어야 합니다")
    @Builder.Default
    private int page = 0;

    @Min(value = 1, message = "페이지 크기는 1 이상이어야 합니다")
    @Max(value = 100, message = "페이지 크기는 100 이하여야 합니다")
    @Builder.Default
    private int size = 20;

    @Builder.Default
    private String sortBy = "createdAt";

    @Builder.Default
    private String sortDir = "DESC";

    // 헬퍼
    public boolean hasTitle() { return title != null && !title.trim().isEmpty(); }
    public boolean hasAnimalName() { return animalName != null && !animalName.trim().isEmpty(); }
    public boolean hasDateTimeRange() { return lostTimeFrom != null || lostTimeTo != null; }
    public boolean hasLocation() { return location != null && !location.trim().isEmpty(); }
    public boolean hasAnimalCategory() { return animalCategory != null && !animalCategory.trim().isEmpty(); }
    public boolean hasAnimalBreed() { return animalBreed != null && !animalBreed.trim().isEmpty(); }
    public boolean hasAgeRange() { return animalAgeFrom != null || animalAgeTo != null; }

    public boolean isDateTimeRangeValid() {
        if (lostTimeFrom != null && lostTimeTo != null) {
            return !lostTimeFrom.isAfter(lostTimeTo);
        }
        return true;
    }

    public boolean isAgeRangeValid() {
        if (animalAgeFrom != null && animalAgeTo != null) {
            return animalAgeFrom <= animalAgeTo;
        }
        return true;
    }
}
