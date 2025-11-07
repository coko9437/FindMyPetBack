package com.busanit501.findmyfet.search_post;

import java.util.List;

public interface SearchService {

    /**
     * 프론트엔드 검색 필터에 사용될 동물 카테고리 및 품종 목록을 반환합니다.
     */
    List<CategoryDto> getCategoryList();

    /**
     * 프론트엔드 검색 필터에 사용될 지역 목록을 반환합니다.
     */
    List<String> getRegionList();

    /**
     * 프론트엔드 검색 필터에 사용될 성별 목록을 반환합니다.
     */
    List<String> getGenderList(); // <<<<<<<<<<<< 메서드 추가

}
