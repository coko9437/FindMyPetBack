package com.busanit501.findmyfet.repository;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.dto.post.FindPetSearchCriteria;
import org.springframework.data.jpa.domain.Specification;

import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;

public class PostSpecification {

    public static Specification<Post> withCriteria(FindPetSearchCriteria criteria) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 제목 부분 일치(소문자 비교)
            if (criteria.hasTitle()) {
                predicates.add(cb.like(
                        cb.lower(root.get("title")),
                        "%" + criteria.getTitle().toLowerCase() + "%"
                ));
            }

            // 동물 이름 부분 일치(소문자 비교)
            if (criteria.hasAnimalName()) {
                predicates.add(cb.like(
                        cb.lower(root.get("animalName")),
                        "%" + criteria.getAnimalName().toLowerCase() + "%"
                ));
            }

            // 분실 시간 범위
            if (criteria.getLostTimeFrom() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("lostTime"), criteria.getLostTimeFrom()));
            }
            if (criteria.getLostTimeTo() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("lostTime"), criteria.getLostTimeTo()));
            }

            // 지역 (부분 일치)
            if (criteria.hasLocation()) {
                predicates.add(cb.like(
                        cb.lower(root.get("location")),
                        "%" + criteria.getLocation().toLowerCase() + "%"
                ));
            }

            // 동물 카테고리
            if (criteria.hasAnimalCategory()) {
                predicates.add(cb.equal(root.get("animalCategory"), criteria.getAnimalCategory()));
            }

            // 품종
            if (criteria.hasAnimalBreed()) {
                predicates.add(cb.equal(root.get("animalBreed"), criteria.getAnimalBreed()));
            }

            /*  ✅ 핵심: enum 참조 제거하고 문자열로 비교 (대소문자 무시)  */

            // postType: DB에 "MISSING"/"SHELTER" 등 문자열로 들어있다는 가정
            if (criteria.getPostType() != null && !criteria.getPostType().isBlank()) {
                predicates.add(cb.equal(
                        cb.upper(root.get("postType")),
                        criteria.getPostType().trim().toUpperCase()
                ));
            }

            // status: DB에 "ACTIVE"/"COMPLETED" 등 문자열로 들어있다는 가정
            if (criteria.getStatus() != null && !criteria.getStatus().isBlank()) {
                predicates.add(cb.equal(
                        cb.upper(root.get("status")),
                        criteria.getStatus().trim().toUpperCase()
                ));
            }

            // 나이 범위
            if (criteria.getAnimalAgeFrom() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("animalAge"), criteria.getAnimalAgeFrom()));
            }
            if (criteria.getAnimalAgeTo() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("animalAge"), criteria.getAnimalAgeTo()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
