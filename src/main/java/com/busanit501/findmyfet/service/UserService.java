package com.busanit501.findmyfet.service;

import com.busanit501.findmyfet.domain.User;
import com.busanit501.findmyfet.dto.UserInfoResponseDTO;
import com.busanit501.findmyfet.dto.UserSignupRequestDTO;
import com.busanit501.findmyfet.dto.UserUpdateRequestDTO;
import com.busanit501.findmyfet.dto.response.LoginUserInfoDTO;
import com.busanit501.findmyfet.dto.response.LoginResponseDTO;
import com.busanit501.findmyfet.repository.UserRepository;
import com.busanit501.findmyfet.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public User signup(UserSignupRequestDTO requestDTO) {
        if (userRepository.findByLoginId(requestDTO.getLoginId()).isPresent()) {
            throw new IllegalArgumentException("이미 사용중인 아이디입니다.");
        }
        if (userRepository.findByEmail(requestDTO.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용중인 이메일입니다.");
        }
        User user = User.builder()
                .loginId(requestDTO.getLoginId())
                .password(passwordEncoder.encode(requestDTO.getPassword()))
                .name(requestDTO.getName())
                .email(requestDTO.getEmail())
                .phoneNumber(requestDTO.getPhoneNumber())
                .address(requestDTO.getAddress())
                .build();
        return userRepository.save(user);
    }

    public LoginResponseDTO login(String loginId, String password) {
        User user = userRepository.findByLoginId(loginId)
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 아이디입니다."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
        String role = user.getRole().name();
        String accessToken = jwtUtil.generateAccessToken(loginId, role);
        String refreshToken = jwtUtil.generateRefreshToken(user.getLoginId(), role);

        user.updateRefreshToken(refreshToken);
        userRepository.save(user);

        LoginUserInfoDTO loginUserInfo = LoginUserInfoDTO.builder()
                .userId(user.getUserId())
                .loginId(user.getLoginId())
                .name(user.getName())
                .role(user.getRole())
                .build();

        return LoginResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(loginUserInfo)
                .build();
    }

    public UserInfoResponseDTO getMe(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        return UserInfoResponseDTO.builder()
                .userId(user.getUserId())
                .loginId(user.getLoginId())
                .name(user.getName())
                .phoneNumber(user.getPhoneNumber())
                .email(user.getEmail())
                .address(user.getAddress())
                .role(user.getRole())
                .build();
    }

    public void updateMe(Long userId, UserUpdateRequestDTO requestDTO) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        if (StringUtils.hasText(requestDTO.getName())) {
            user.setName(requestDTO.getName());
        }
        if (StringUtils.hasText(requestDTO.getPhoneNumber())) {
            user.setPhoneNumber(requestDTO.getPhoneNumber());
        }
        if (StringUtils.hasText(requestDTO.getAddress())) {
            user.setAddress(requestDTO.getAddress());
        }
        if (StringUtils.hasText(requestDTO.getEmail())) {
            user.setEmail(requestDTO.getEmail());
        }

        if (requestDTO.getPasswordChange() != null) {
            UserUpdateRequestDTO.PasswordChangeDTO passwordChange = requestDTO.getPasswordChange();
            if (!passwordEncoder.matches(passwordChange.getCurrentPassword(), user.getPassword())) {
                throw new IllegalArgumentException("현재 비밀번호가 일치하지 않습니다.");
            }
            if (!StringUtils.hasText(passwordChange.getNewPassword())) {
                throw new IllegalArgumentException("새 비밀번호를 입력해주세요.");
            }
            user.setPassword(passwordEncoder.encode(passwordChange.getNewPassword()));
        }
        userRepository.save(user);
    }

    public String refreshAccessToken(String refreshToken) {
        String loginId = jwtUtil.validateToken(refreshToken).getSubject();

        User user = userRepository.findByLoginId(loginId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        if (!refreshToken.equals(user.getRefreshToken())) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다.");
        }
        String role = user.getRole().name();
        return jwtUtil.generateAccessToken(loginId, role);
    }
}