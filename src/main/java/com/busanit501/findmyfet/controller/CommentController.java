package com.busanit501.findmyfet.controller;

import com.busanit501.findmyfet.dto.CommentDTO;
import com.busanit501.findmyfet.security.UserDetailsImpl;
import com.busanit501.findmyfet.service.CommentService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Log4j2
public class CommentController {

    private final CommentService commentService;

    // ✅ 수정된 메서드
    @GetMapping("/posts/{postId}/comments")
    public ResponseEntity<Page<CommentDTO>> getCommentList(
            @PathVariable Long postId,
            // 클라이언트에서 page, size, sort 파라미터를 받음
            // 기본값: page=0, size=10, 정렬=최신순(createdAt DESC)
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("getCommentList 호출 (페이징 적용), postId: {}, pageable: {}", postId, pageable);
        Page<CommentDTO> commentPage = commentService.getCommentsByPostId(postId, pageable);
        return ResponseEntity.ok(commentPage);
    }

    @PostMapping(value = "/posts/{postId}/comments", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CommentDTO> createComment(@PathVariable Long postId,
                                                    @RequestPart("commentDTO") CommentDTO commentDTO,
                                                    @RequestPart(value = "imageFile", required = false) MultipartFile imageFile,
                                                    @AuthenticationPrincipal UserDetailsImpl userDetails) {
        Long userId = userDetails.getUserid();
        log.info("createComment 호출, postId: {}, by user: {}", postId, userId);

        commentDTO.setPostId(postId);
        CommentDTO createdComment = commentService.createComment(commentDTO, userId, imageFile);
        return ResponseEntity.status(HttpStatus.CREATED).contentType(MediaType.APPLICATION_JSON).body(createdComment);
    }

    @PutMapping(value = "/comments/{commentId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CommentDTO> updateComment(@PathVariable Long commentId,
                                                    @RequestPart("commentDTO") CommentDTO commentDTO,
                                                    @RequestPart(value = "imageFile", required = false) MultipartFile imageFile,
                                                    @AuthenticationPrincipal UserDetailsImpl userDetails) {
        Long userId = userDetails.getUserid();
        log.info("updateComment 호출, commentId: {}, by user: {}", commentId, userId);

        CommentDTO updatedComment = commentService.updateComment(commentId, commentDTO, userId, imageFile);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(updatedComment);
    }

    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<Void> deleteComment(@PathVariable Long commentId,
                                              @AuthenticationPrincipal UserDetailsImpl userDetails) {
        Long userId = userDetails.getUserid();
        log.info("deleteComment 호출, commentId: {}, by user: {}", commentId, userId);

        commentService.deleteComment(commentId, userId);
        return ResponseEntity.noContent().build();
    }
}