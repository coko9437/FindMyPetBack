package com.busanit501.findmyfet.search_post;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class SearchController {

    private final SearchService searchService;


    @GetMapping("/categories")
    public ResponseEntity<List<CategoryDto>> getCategoryList() {
        List<CategoryDto> categories = searchService.getCategoryList();
        return ResponseEntity.ok(categories);
    }


    @GetMapping("/regions")
    public ResponseEntity<List<String>> getRegionList() {
        List<String> regions = searchService.getRegionList();
        return ResponseEntity.ok(regions);
    }

    @GetMapping("/genders") // <<<<<<<<<<<< API 추가
    public ResponseEntity<List<String>> getGenderList() {
        List<String> genders = searchService.getGenderList();
        return ResponseEntity.ok(genders);
    }

}
