package com.busanit501.findmyfet.dto.error;

import lombok.Getter;
import java.util.List;

// 역할: 기존 ErrorResponse를 상속받아, 상세 에러 목록(details)을 추가로 가짐
@Getter
public class ErrorResponseWithDetails extends ErrorResponse {
    private final List<ErrorDetail> details;

    public ErrorResponseWithDetails(String code, String message, List<ErrorDetail> details) {
        super(code, message);
        this.details = details;
    }
}