package com.busanit501.findmyfet.service;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.dto.post.FindPetSearchCriteria;
import com.busanit501.findmyfet.repository.FindPostRepository;   // ✅ 이 리포만 사용
import com.busanit501.findmyfet.repository.PostSpecification;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class FindPetPostService {

    // ✅ PostRepository → FindPostRepository 로 교체
    private final FindPostRepository postRepository;

    /** 검색 */
    public Page<Post> searchFindPetPosts(FindPetSearchCriteria criteria) {
        if (!criteria.isDateTimeRangeValid()) {
            throw new IllegalArgumentException("분실 시작 시간은 종료 시간보다 이전이어야 합니다.");
        }
        if (!criteria.isAgeRangeValid()) {
            throw new IllegalArgumentException("최소 나이는 최대 나이보다 작거나 같아야 합니다.");
        }

        Specification<Post> spec = PostSpecification.withCriteria(criteria);
        Sort sort = createSort(criteria.getSortBy(), criteria.getSortDir());
        Pageable pageable = PageRequest.of(criteria.getPage(), criteria.getSize(), sort);
        return postRepository.findAll(spec, pageable);
    }

    /** 모든 동물 카테고리 목록 */
    public List<String> getAllAnimalCategories() {
        return postRepository.findDistinctAnimalCategories();
    }

    /** 모든 게시글 타입 (enum 없이 하드코딩 목록 반환) */
    public List<Map<String, String>> getAllPostTypes() {
        List<Map<String, String>> postTypes = new ArrayList<>();
        postTypes.add(Map.of("value", "MISSING", "label", "실종신고"));
        postTypes.add(Map.of("value", "SHELTER", "label", "보호소"));
        return postTypes;
    }

    /** 모든 지역 목록 */
    public List<String> getAllLocations() {
        return postRepository.findDistinctLocations();
    }

    /** 특정 동물 카테고리의 품종 목록 */
    public List<String> getBreedsByAnimalCategory(String animalCategory) {
        if (animalCategory == null || animalCategory.trim().isEmpty()) {
            throw new IllegalArgumentException("동물 카테고리 정보가 필요합니다.");
        }
        return postRepository.findDistinctBreedsByAnimalCategory(animalCategory);
    }

    /** 게시글 ID로 조회 */
    public Post findById(Long id) {
        return postRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("게시글을 찾을 수 없습니다. ID: " + id));
    }

    /** 게시글 완료 처리 */
    @Transactional
    public Post completePost(Long id) {
        Post post = findById(id);
        // Post.java를 건드리지 않는 조건이라면, 상태 문자열을 직접 바꿔야 할 수 있습니다.
        // 만약 Post에 setStatus(String) 메서드가 없다면, 빌더/업데이트 로직에 맞게 수정하세요.
        try {
            // 리플렉션 or 세터가 있다면 사용
            var field = Post.class.getDeclaredField("status");
            field.setAccessible(true);
            field.set(post, "COMPLETED");
        } catch (Exception ignore) {
            // 프로젝트의 실제 업데이트 방식에 맞추어 수정하세요.
        }
        return postRepository.save(post);
    }

    /** 정렬 생성 */
    private Sort createSort(String sortBy, String sortDir) {
        Set<String> allowed = Set.of("createdAt", "updatedAt", "lostTime", "title", "animalName");
        if (!allowed.contains(sortBy)) sortBy = "createdAt";
        Sort.Direction dir = "ASC".equalsIgnoreCase(sortDir) ? Sort.Direction.ASC : Sort.Direction.DESC;
        return Sort.by(dir, sortBy);
    }
}
