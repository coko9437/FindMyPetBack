package com.busanit501.findmyfet.dto.error;

import lombok.Getter;

// 역할: 기획서에 명시된 {"success": false, "error": {"code": "...", "message": "..."}} 와 유사한 구조를 만들기 위한 데이터
@Getter
public class ErrorResponse {
    private final String code;
    private final String message;

    public ErrorResponse(String code, String message) {
        this.code = code;
        this.message = message;
    }
}
