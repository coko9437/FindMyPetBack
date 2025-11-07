package com.busanit501.findmyfet.repository.post;


import com.busanit501.findmyfet.domain.post.Post;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostRepository extends JpaRepository<Post, Long>, PostRepositoryCustom  {

    // User 엔티티의 userid 필드를 기준으로 찾도록 수정
    List<Post> findByUser_UserIdOrderByCreatedAtDesc(Long userId);
}
