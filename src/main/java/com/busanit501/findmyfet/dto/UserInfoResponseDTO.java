package com.busanit501.findmyfet.dto;

import com.busanit501.findmyfet.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserInfoResponseDTO {

    private Long userId;
    private String loginId;
    private String name;
    private String phoneNumber;
    private String email;
    private String address;
    private Role role;

}
