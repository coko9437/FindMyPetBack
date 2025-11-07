package com.busanit501.findmyfet.search_post;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

//동물 Category(개, 고양이)와 하위 Breed(품종) 목록을 담는역할
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CategoryDto {
    private String category;
    private List<String> breeds;

}
