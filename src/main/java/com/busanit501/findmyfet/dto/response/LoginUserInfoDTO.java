package com.busanit501.findmyfet.dto.response;

import com.busanit501.findmyfet.domain.Role;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginUserInfoDTO {
    private Long userId;
    private String loginId;
    private String name;
    private Role role;
}
