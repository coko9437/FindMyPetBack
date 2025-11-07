// PostRepositoryCustomImpl.java

package com.busanit501.findmyfet.repository.post;

import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.domain.post.QPost;
import com.busanit501.findmyfet.dto.post.FindPetSearchCriteria;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.util.StringUtils;

import java.util.List;

@RequiredArgsConstructor
public class PostRepositoryCustomImpl implements PostRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<Post> search(FindPetSearchCriteria criteria, Pageable pageable) {
        QPost post = QPost.post;
        BooleanBuilder booleanBuilder = new BooleanBuilder();

        // [수정] criteria 객체의 필드를 사용하도록 전체 로직 변경

        // ===== 상세 검색 조건 (FindPetSearchCriteria 기준) =====
        if (criteria.hasTitle()) {
            booleanBuilder.and(post.title.contains(criteria.getTitle()));
        }
        if (criteria.hasAnimalName()) {
            booleanBuilder.and(post.animalName.contains(criteria.getAnimalName()));
        }
        if (criteria.getLostTimeFrom() != null) {
            booleanBuilder.and(post.lostTime.goe(criteria.getLostTimeFrom()));
        }
        if (criteria.getLostTimeTo() != null) {
            booleanBuilder.and(post.lostTime.loe(criteria.getLostTimeTo()));
        }
        if (criteria.hasLocation()) {
            booleanBuilder.and(post.location.contains(criteria.getLocation()));
        }
        if (criteria.hasAnimalCategory()) {
            booleanBuilder.and(post.animalCategory.eq(criteria.getAnimalCategory()));
        }
        if (criteria.hasAnimalBreed()) {
            booleanBuilder.and(post.animalBreed.eq(criteria.getAnimalBreed()));
        }
        if (StringUtils.hasText(criteria.getPostType())) {
            booleanBuilder.and(post.postType.stringValue().equalsIgnoreCase(criteria.getPostType()));
        }
        if (StringUtils.hasText(criteria.getStatus())) {
            booleanBuilder.and(post.status.stringValue().equalsIgnoreCase(criteria.getStatus()));
        }
        // (기타 animalAge 등 필요한 조건이 있다면 여기에 추가)

        // 쿼리 생성 (N+1 문제 방지를 위해 fetchJoin() 유지)
        JPAQuery<Post> query = queryFactory.selectFrom(post)
                .leftJoin(post.user).fetchJoin() // 작성자 정보를 함께 조회
                .where(booleanBuilder)
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize());

        // 정렬 조건 적용 (Pageable 객체에 정렬 정보가 포함되어 있음)
        // Querydsl은 Pageable의 정렬을 자동으로 처리하지 않으므로 수동으로 추가해주는 것이 좋습니다.
        // PostServiceImpl에서 이미 Pageable에 정렬 정보를 담았으므로 여기서는 orderBy를 추가합니다.
        pageable.getSort().stream().forEach(order -> {
            // 정렬 로직 추가 (필요 시 더 복잡한 정렬 처리 가능)
        });
        // 기본 정렬
        query.orderBy(post.createdAt.desc());


        List<Post> content = query.fetch();

        // 전체 카운트 쿼리
        JPAQuery<Long> countQuery = queryFactory.select(post.count())
                .from(post)
                .where(booleanBuilder);

        long total = countQuery.fetchOne() != null ? countQuery.fetchOne() : 0;

        return new PageImpl<>(content, pageable, total);
    }

    @Override
    public long countByPostType(com.busanit501.findmyfet.domain.post.PostType postType) {
        QPost post = QPost.post;
        return queryFactory.select(post.count())
                .from(post)
                .where(post.postType.eq(postType))
                .fetchOne();
    }

    @Override
    public long countByStatus(com.busanit501.findmyfet.domain.post.Status status) {
        QPost post = QPost.post;
        return queryFactory.select(post.count())
                .from(post)
                .where(post.status.eq(status))
                .fetchOne();
    }

    @Override
    public long countByCreatedAtAfter(java.time.LocalDateTime dateTime) {
        QPost post = QPost.post;
        return queryFactory.select(post.count())
                .from(post)
                .where(post.createdAt.after(dateTime))
                .fetchOne();
    }

    @Override
    public java.util.List<com.busanit501.findmyfet.domain.post.Post> findTop5ByStatusOrderByUpdatedAtDesc(com.busanit501.findmyfet.domain.post.Status status) {
        QPost post = QPost.post;
        return queryFactory.selectFrom(post)
                .where(post.status.eq(status))
                .orderBy(post.updatedAt.desc())
                .limit(5)
                .fetch();
    }

    @Override
    public long countAllPosts() {
        QPost post = QPost.post;
        return queryFactory.select(post.count())
                .from(post)
                .fetchOne();
    }
}