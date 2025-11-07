package com.busanit501.findmyfet.domain.post;

import lombok.Getter;

@Getter
public enum AnimalGender {

    MALE("수컷"),
    FEMALE("암컷"),
    UNKNOWN("모름");

    private final String description;

    AnimalGender(String description) {
        this.description = description;
    }

}
