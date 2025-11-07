package com.busanit501.findmyfet.dto.response;

import lombok.Getter;

@Getter
public class CommonResponse<T> {

    private final boolean success;
    private final String message;
    private final T data;

    private CommonResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public static <T> CommonResponse<T> of(String message, T data) {
        return new CommonResponse<>(true, message, data);
    }

    public static CommonResponse<Void> of(String message) {
        return new CommonResponse<>(true, message, null);
    }
}
