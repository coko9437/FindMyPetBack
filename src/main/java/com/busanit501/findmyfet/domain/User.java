package com.busanit501.findmyfet.domain;


import com.busanit501.findmyfet.domain.post.Post;
import jakarta.persistence.*;
import lombok.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.HashSet;
import java.util.List;

@JsonIgnoreProperties({"hibernateLazyInitializer","handler"})

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class User extends BaseEntity { // 베이스 엔티티 상속
    @JsonIgnore               // ✅ 순환/프록시 직렬화 방지
    @OneToMany(mappedBy = "user")
    private List<Post> posts;


    @Id // primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 키 자동생성
    @Column(name = "user_id") // DB 컬럼명을 명시적으로 지정하는 것이 좋습니다.
    private Long userId;

    @Column(unique = true, nullable = false)
    private String loginId;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String phoneNumber;

    @Column(nullable = false , unique = true)
    private String email;

    @Column(nullable = false)
    private String address;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private Role role = Role.USER;

    private String refreshToken;

    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }


}
