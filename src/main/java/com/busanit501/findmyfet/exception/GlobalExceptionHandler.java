package com.busanit501.findmyfet.exception;
import com.busanit501.findmyfet.dto.error.ErrorDetail;
import com.busanit501.findmyfet.dto.error.ErrorResponse;
import com.busanit501.findmyfet.dto.error.ErrorResponseWithDetails;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

// 모든 컨트롤러에서 발생하는 예외를 잡아서 처리해주는 클래스
@RestControllerAdvice
public class GlobalExceptionHandler {

    // [기존 코드] 특정 예외(IllegalArgumentException)를 잡아서 하나의 메소드에서 공통 처리
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        // 'BAD_REQUEST' 코드와 예외 메시지를 담은 ErrorResponse 객체 생성
        ErrorResponse response = new ErrorResponse("BAD_REQUEST", ex.getMessage());
        // 400 (Bad Request) 상태 코드와 함께 ErrorResponse를 클라이언트에게 반환
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // [기존 코드] 권한 관련 예외 처리
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex) {
        ErrorResponse response = new ErrorResponse("FORBIDDEN", ex.getMessage());
        // 403 (Forbidden) 상태 코드와 함께 응답
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // Controller에서, @Valid 유효성 검사 실패 시 기획서의 응답 형식과 똑같은, 깔끔하고 일관된 JSON 응답이 반환
    // [추가된 코드] @Valid 유효성 검사 실패 시 예외 처리
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseWithDetails> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // 1. 유효성 검사에 실패한 모든 필드와 메시지를 가져와 List<ErrorDetail>로 변환
        List<ErrorDetail> details = ex.getBindingResult().getAllErrors().stream()
                .map(error -> {
                    String fieldName = (error instanceof FieldError) ? ((FieldError) error).getField() : error.getObjectName();
                    return new ErrorDetail(fieldName, error.getDefaultMessage());
                })
                .collect(Collectors.toList());

        // 2. 기획서 형식에 맞는 응답 객체 생성
        ErrorResponseWithDetails response = new ErrorResponseWithDetails("VALIDATION_ERROR", "입력값이 올바르지 않습니다.", details);

        // 3. 400 (Bad Request) 상태 코드와 함께 응답
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }
}