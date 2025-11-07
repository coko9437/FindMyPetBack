package com.busanit501.findmyfet.domain.post;

import jakarta.persistence.*;

import lombok.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString(exclude = {"post", "comment"}) // 순환참조 방지함
public class Image {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "image_id")
    private Long id;

    @Column(name = "image_url", nullable = false)
    private String imageUrl; // 이미지 파일 경로

    // N:1, Image(N) : Post(1)
    // 이미지를 조회할 때 연관된 Post 정보가 항상 필요하진 않으므로 LAZY(지연로딩) 설정
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "post_id") // 외래키 컬럼명 지정
    @com.fasterxml.jackson.annotation.JsonIgnore
    private Post post;

    // N:1, Image(N) : Comment(1)
    // Comment 엔티티 생성 후 주석 해제 및 import 필요
    // @ManyToOne(fetch = FetchType.LAZY)
    // @JoinColumn(name = "comment_id")
    // private Comment comment;


    //== 연관관계 편의 메서드 ==//
    // Post 정보가 업데이트 될 때, Image 쪽에서도 Post 정보를 동기화
    public void setPost(Post post) {
        this.post = post;
    }

//    // Comment 정보가 업데이트 될 때, Image 쪽에서도 Comment 정보를 동기화
//    public void setComment(Comment comment) {
//        this.comment = comment;
//    }
}
