package com.busanit501.findmyfet.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserUpdateRequestDTO {

    private String name;
    private String phoneNumber;
    private String email;
    private String address;
    private PasswordChangeDTO passwordChange;

    @Data
    public static class PasswordChangeDTO {
        private String currentPassword;
        private String newPassword;
    }
}
