package com.busanit501.findmyfet.repository;

import com.busanit501.findmyfet.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 로그인 아이디로 사용자를 조회하는 쿼리 메서드
    Optional<User> findByLoginId(String loginId);

    Optional<User> findByEmail(String email);

}
