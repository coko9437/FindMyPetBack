package com.busanit501.findmyfet.repository;

import com.busanit501.findmyfet.domain.Comment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {

    // ✅ 수정된 부분: List<Comment> -> Page<Comment>, Pageable 파라미터 추가
    // 특정 게시글의 댓글을 페이징 처리하여 찾는 메서드
    Page<Comment> findByPost_Id(Long postId, Pageable pageable);

}