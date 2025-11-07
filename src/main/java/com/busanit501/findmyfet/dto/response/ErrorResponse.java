package com.busanit501.findmyfet.dto.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ErrorResponse {

    private final boolean success = false;
    private final ErrorDetails error;

    @Getter
    @RequiredArgsConstructor
    public static class ErrorDetails {
        private final String code;
        private final String message;
    }

    public static ErrorResponse of(String code, String message) {
        return new ErrorResponse(new ErrorDetails(code, message));
    }
}
