package com.busanit501.findmyfet.controller;

import com.busanit501.findmyfet.dto.response.CommonResponse;
import com.busanit501.findmyfet.dto.UserInfoResponseDTO;
import com.busanit501.findmyfet.service.AdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Log4j2
public class AdminController {

    private final AdminService adminService;

    // 6.1 모든 게시글 관리 (GET /api/admin/posts)
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/posts")
    public ResponseEntity<CommonResponse<Page<com.busanit501.findmyfet.domain.post.Post>>> getAllPosts(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size) {
        log.info("Admin: getAllPosts 호출 (page: {}, size: {})", page, size);
        Pageable pageable = PageRequest.of(page, size);
        Page<com.busanit501.findmyfet.domain.post.Post> posts = adminService.getAllPosts(pageable);
        return ResponseEntity.ok(CommonResponse.of("게시글 목록 조회 성공", posts));
    }

    // 6.2 게시글 강제 삭제 (DELETE /api/admin/posts/{postId})
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/posts/{postId}")
    public ResponseEntity<CommonResponse<String>> deletePost(@PathVariable Long postId) {
        log.info("Admin: deletePost 호출 (postId: {})", postId);
        adminService.deletePost(postId);
        return ResponseEntity.ok(CommonResponse.of("게시글이 성공적으로 삭제되었습니다.", null));
    }

    // 6.3 댓글 강제 삭제 (DELETE /api/admin/comments/{commentId})
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<CommonResponse<String>> deleteComment(@PathVariable Long commentId) {
        log.info("Admin: deleteComment 호출 (commentId: {})", commentId);
        adminService.deleteComment(commentId);
        return ResponseEntity.ok(CommonResponse.of("댓글이 성공적으로 삭제되었습니다.", null));
    }

    // 6.4 사용자 목록 조회 (GET /api/admin/users)
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<CommonResponse<List<UserInfoResponseDTO>>> getAllUsers() {
        log.info("Admin: getAllUsers 호출");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            log.info("Authentication Principal: {}", authentication.getPrincipal());
            log.info("Authentication Authorities: {}", authentication.getAuthorities());
        } else {
            log.info("Authentication object is null.");
        }
        List<UserInfoResponseDTO> users = adminService.getAllUsers();
        return ResponseEntity.ok(CommonResponse.of("사용자 목록 조회 성공", users));
    }
}
