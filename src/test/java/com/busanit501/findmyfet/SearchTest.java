package com.busanit501.findmyfet;

import com.busanit501.findmyfet.domain.User;
import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.domain.post.PostType;
import com.busanit501.findmyfet.domain.post.Status;
import com.busanit501.findmyfet.repository.post.PostRepository;
import com.busanit501.findmyfet.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
class SearchTest {

    @Autowired PostRepository postRepository;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private User testUser;

    @BeforeEach
    void setUp() {
        postRepository.deleteAllInBatch();
        userRepository.deleteAllInBatch();

        testUser = User.builder()
                .email("testuser@example.com")
                .password(passwordEncoder.encode("password123"))
                .name("TestUser")
                .loginId("testuser")
                .phoneNumber("010-1234-5678")
                .address("부산시")
                .build();
        userRepository.save(testUser);

        for (int i = 1; i <= 5; i++) {
            Post post = Post.builder()
                    .title("테스트 게시글 " + i)
                    .content("이것은 테스트 게시글 내용입니다 " + i)
                    .animalName("테스트 동물 " + i)
                    .animalAge(i)
                    .animalCategory(i % 2 == 0 ? "개" : "고양이")
                    .animalBreed(i % 2 == 0 ? "푸들" : "코숏")
                    .lostTime(LocalDateTime.now().minusDays(i))
                    .latitude(35.12345 + i * 0.001)
                    .longitude(129.01234 + i * 0.001)
                    .location("테스트 장소 " + i)
                    .postType(PostType.MISSING)
                    .status(Status.ACTIVE)
                    .user(testUser)
                    .build();
            postRepository.save(post);
        }
    }

    @Test
    @DisplayName("더미 5건 저장 확인")
    void 저장_검증() {
        List<Post> all = postRepository.findAll();
        assertThat(all).hasSize(5);
        assertThat(all.get(0).getUser().getEmail()).isEqualTo("testuser@example.com");
    }
}
