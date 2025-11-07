package com.busanit501.findmyfet.search_post;

import com.busanit501.findmyfet.domain.post.AnimalGender;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SearchServiceImpl implements SearchService {

    @Override
    public List<CategoryDto> getCategoryList() {
        // 기획서 기반 하드코딩
        // 추후 이 데이터를 DB에서 관리하도록 확장할 수 있습니다.
        CategoryDto dogCategory = new CategoryDto("개", List.of("말티즈", "푸들", "골든리트리버", "진돗개"));
        CategoryDto catCategory = new CategoryDto("고양이", List.of("코리안숏헤어", "페르시안", "러시안블루", "샴"));

        return List.of(dogCategory, catCategory);
    }

    @Override
    public List<String> getRegionList() {
        // 기획서 기반 하드코딩
        // Post의 location 필드에 입력될 값들과 일치해야
        return List.of(
                "서울시", "부산시", "대구시", "인천시", "광주시",
                "대전시", "울산시", "경기도", "강원도"
                // 필요에 따라 다른 지역 추가
        );
    }

    @Override
    public List<String> getGenderList() {
        // Enum의 모든 값을 가져와서 "MALE", "FEMALE", "UNKNOWN" 문자열 리스트로 반환
        return Arrays.stream(AnimalGender.values())
                .map(Enum::name)
                .collect(Collectors.toList());
    }
}
