package com.busanit501.findmyfet.service.post;


import com.busanit501.findmyfet.dto.paging.PageRequestDto;
import com.busanit501.findmyfet.dto.paging.PageResponseDto;
import com.busanit501.findmyfet.dto.post.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface PostService {

    // [수정] PageRequestDto -> FindPetSearchCriteria로 변경
    PageResponseDto<PostListResponseDto> findAllPosts(FindPetSearchCriteria criteria);

    // 게시판 전체조회 -> 페이징 처리 + 전체조회로 바꿈.
//    List<PostListResponseDto> findAllPosts();

    // 게시글 상세 조회
    PostDetailResponseDto findPostById(Long postId);

    // 게시글 등록 (userId 파라미터 추가)
    Long createPost(PostCreateRequestDto requestDto, List<MultipartFile> images, Long userId);

    // 게시글 수정 (userId 파라미터 추가)
    void updatePost(Long postId, PostUpdateRequestDto requestDto, List<MultipartFile> newImages, Long userId);

    // 게시글 삭제 (userId 파라미터 추가)
    void deletePost(Long postId, Long userId);

    // 게시글 찾기 완료 처리 (userId 파라미터 추가)
    void completePost(Long postId, Long userId);

    // 내가 쓴 글 목록 조회 (메서드 추가)
    List<MyPostResponseDto> findMyPosts(Long userId);

}