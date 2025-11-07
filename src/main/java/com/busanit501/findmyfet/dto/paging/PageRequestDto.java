package com.busanit501.findmyfet.dto.paging;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;



@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PageRequestDto {

    @Builder.Default
    @Min(value = 1)
    @Positive
    private int page = 1;

    @Builder.Default
    @Min(value = 9) // 최소 사이즈를 9로 설정
    @Max(value = 100)
    @Positive
    private int size = 9; // <<<<< 기본 사이즈를 9로 변경 (3x3 그리드)

    // '찾아줘요' 프로젝트의 검색 조건에 맞게 필드 수정
    private String type;     // MISSING | SHELTER
    private String category; // 동물 카테고리 (예: "개", "고양이")
    private String region;   // 지역
    private String keyword;  // 검색 키워드 (제목, 내용 등)

    private String gender; // <<<<<<<<<<<< 검색 조건 추가

    // Spring Data JPA의 Pageable 객체를 생성하는 헬퍼 메소드
    public Pageable getPageable(String... props) {
        return PageRequest.of(this.page - 1, this.size, Sort.by(props).descending());
    }
}


