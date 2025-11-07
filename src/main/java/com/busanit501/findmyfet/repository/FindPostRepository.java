package com.busanit501.findmyfet.repository;

import com.busanit501.findmyfet.domain.post.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindPostRepository extends JpaRepository<Post, Long>, JpaSpecificationExecutor<Post> {

    /** 모든 지역(location) 목록 */
    @Query("SELECT DISTINCT p.location FROM Post p WHERE p.location IS NOT NULL ORDER BY p.location")
    List<String> findDistinctLocations();

    /** 모든 동물 카테고리 목록 */
    @Query("SELECT DISTINCT p.animalCategory FROM Post p WHERE p.animalCategory IS NOT NULL ORDER BY p.animalCategory")
    List<String> findDistinctAnimalCategories();

    /** 특정 동물 카테고리의 모든 품종 목록 */
    @Query("SELECT DISTINCT p.animalBreed FROM Post p WHERE p.animalCategory = :animalCategory AND p.animalBreed IS NOT NULL ORDER BY p.animalBreed")
    List<String> findDistinctBreedsByAnimalCategory(@Param("animalCategory") String animalCategory);

    /** 특정 지역의 게시글 수 */
    @Query("SELECT COUNT(p) FROM Post p WHERE p.location = :location")
    long countByLocation(@Param("location") String location);

    /*  ✅ enum 의존 제거: 아래 두 메서드를 String으로 변경  */

    /** 상태별 게시글 (상태 문자열: 'ACTIVE' / 'COMPLETED') */
    List<Post> findByStatusOrderByCreatedAtDesc(String status);

    /** 타입+상태별 게시글 (타입: 'MISSING' / 'SHELTER', 상태: 'ACTIVE' / 'COMPLETED') */
    List<Post> findByPostTypeAndStatusOrderByCreatedAtDesc(String postType, String status);

    /** 특정 사용자의 게시글 */
    @Query("SELECT p FROM Post p WHERE p.user.id = :userId ORDER BY p.createdAt DESC")
    List<Post> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);
}
