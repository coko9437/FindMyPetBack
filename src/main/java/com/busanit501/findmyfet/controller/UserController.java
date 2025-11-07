package com.busanit501.findmyfet.controller;

import com.busanit501.findmyfet.dto.RefreshTokenRequestDTO;
import com.busanit501.findmyfet.dto.response.LoginResponseDTO;
import com.busanit501.findmyfet.domain.User;
import com.busanit501.findmyfet.dto.UserInfoResponseDTO;
import com.busanit501.findmyfet.dto.UserLoginRequestDTO;
import com.busanit501.findmyfet.dto.UserSignupRequestDTO;
import com.busanit501.findmyfet.dto.UserUpdateRequestDTO;
import com.busanit501.findmyfet.dto.response.CommonResponse;
import com.busanit501.findmyfet.security.UserDetailsImpl;
import com.busanit501.findmyfet.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class UserController {

    private final UserService userService;

    @PostMapping("/auth/signup")
    public ResponseEntity<CommonResponse<UserInfoResponseDTO>> signup(@RequestBody UserSignupRequestDTO requestDTO) {
        User newUser = userService.signup(requestDTO);
        UserInfoResponseDTO userInfo = UserInfoResponseDTO.builder()
                .userId(newUser.getUserId())
                .loginId(newUser.getLoginId())
                .name(newUser.getName())
                .phoneNumber(newUser.getPhoneNumber())
                .email(newUser.getEmail())
                .address(newUser.getAddress())
                .role(newUser.getRole())
                .build();

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(CommonResponse.of("회원가입이 완료되었습니다.", userInfo));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<CommonResponse<LoginResponseDTO>> login(@RequestBody UserLoginRequestDTO requestDTO) {
        LoginResponseDTO loginResponse = userService.login(requestDTO.getLoginId(), requestDTO.getPassword());
        return ResponseEntity.ok(CommonResponse.of("로그인 성공", loginResponse));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<CommonResponse<Map<String, String>>> refreshAccessToken(@RequestBody RefreshTokenRequestDTO requestDTO) {
        String newAccessToken = userService.refreshAccessToken(requestDTO.getRefreshToken());
        return ResponseEntity.ok(CommonResponse.of("Access Token이 재발급되었습니다.", Map.of("accessToken", newAccessToken)));
    }

    @GetMapping("/users/me")
    public ResponseEntity<CommonResponse<UserInfoResponseDTO>> getMe(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        Long userId = userDetails.getUserid(); // Get userId from UserDetailsImpl
        UserInfoResponseDTO responseDTO = userService.getMe(userId);
        return ResponseEntity.ok(CommonResponse.of("내 정보 조회 성공", responseDTO));
    }

    @PutMapping("/users/me")
    public ResponseEntity<CommonResponse<Void>> updateMe(@AuthenticationPrincipal UserDetailsImpl userDetails, @RequestBody UserUpdateRequestDTO requestDTO) {
        Long userId = userDetails.getUserid();
        userService.updateMe(userId, requestDTO);
        return ResponseEntity.ok(CommonResponse.of("회원 정보가 수정되었습니다."));
    }
}