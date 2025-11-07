package com.busanit501.findmyfet.repository.post;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.domain.post.PostType;
import com.busanit501.findmyfet.domain.post.Status;
import com.busanit501.findmyfet.dto.paging.PageRequestDto;
import com.busanit501.findmyfet.dto.post.FindPetSearchCriteria;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;

public interface PostRepositoryCustom {

    // [수정] PageRequestDto -> FindPetSearchCriteria로 변경
    Page<Post> search(FindPetSearchCriteria criteria, Pageable pageable);

    // 통계용 메서드
    long countByPostType(PostType postType);
    long countByStatus(Status status);
    long countByCreatedAtAfter(LocalDateTime dateTime);
    List<Post> findTop5ByStatusOrderByUpdatedAtDesc(Status status);
    long countAllPosts();
}
