package com.busanit501.findmyfet.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserSignupRequestDTO {

    private String loginId;
    private String password;
    private String name;
    private String phoneNumber;
    private String email;
    private String address;

}
