package com.busanit501.findmyfet.config;

import com.busanit501.findmyfet.domain.User;
import com.busanit501.findmyfet.domain.post.AnimalGender;
import com.busanit501.findmyfet.domain.post.Image;
import com.busanit501.findmyfet.domain.post.Post;
import com.busanit501.findmyfet.dto.post.MyPostResponseDto;
import com.busanit501.findmyfet.dto.post.PostDetailResponseDto;
import com.busanit501.findmyfet.dto.post.PostListResponseDto;
import com.busanit501.findmyfet.dto.user.AuthorDto;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.stream.Collectors;

// 작업 순서2
@Configuration
public class RootConfig {

    @Bean
    public ModelMapper getMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration()
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE)
                .setMatchingStrategy(MatchingStrategies.STRICT); // LOOSE 보다 STRICT 추천

        // User -> AuthorDto 매핑 (공통으로 사용될 수 있으므로 먼저 정의)
        modelMapper.createTypeMap(User.class, AuthorDto.class);

        // Post -> PostDetailResponseDto 매핑 설정
        modelMapper.createTypeMap(Post.class, PostDetailResponseDto.class)
                .addMappings(mapper -> {
                    mapper.map(Post::getId, PostDetailResponseDto::setPostId);

                    mapper.using((Converter<AnimalGender, String>) context ->
                            context.getSource() == null ? null : context.getSource().getDescription()
                    ).map(Post::getGender, PostDetailResponseDto::setGender);

                    mapper.using((Converter<List<Image>, List<String>>) context ->
                            context.getSource() == null ? null : context.getSource().stream()
                                    .map(Image::getImageUrl)
                                    .collect(Collectors.toList())
                    ).map(Post::getImages, PostDetailResponseDto::setImageUrls);

                    // author 필드는 Post 엔티티의 user 필드를 사용하여 매핑하도록 명시
                    mapper.map(Post::getUser, PostDetailResponseDto::setAuthor);
                });

        // Post -> PostListResponseDto 매핑 설정
        modelMapper.createTypeMap(Post.class, PostListResponseDto.class)
                .addMappings(mapper -> {
                    mapper.map(Post::getId, PostListResponseDto::setPostId);

                    mapper.using((Converter<List<Image>, String>) context ->
                            (context.getSource() == null || context.getSource().isEmpty()) ?
                                    null : context.getSource().get(0).getImageUrl()
                    ).map(Post::getImages, PostListResponseDto::setThumbnailUrl);

                    // author 필드는 Post 엔티티의 user 필드를 사용하여 매핑하도록 명시
                    mapper.using((Converter<User, AuthorDto>) context -> {
                        User source = context.getSource();
                        if (source == null) {
                            return null;
                        }
                        return AuthorDto.builder()
                                .userId(source.getUserId())
                                .name(source.getName())
                                .build();
                    }).map(Post::getUser, PostListResponseDto::setAuthor);
                });

        // Post -> MyPostResponseDto 매핑 설정
        modelMapper.createTypeMap(Post.class, MyPostResponseDto.class)
                .addMappings(mapper -> {
                    mapper.map(Post::getId, MyPostResponseDto::setPostId);
                });

        // Comment -> CommentDTO 매핑 설정
        modelMapper.createTypeMap(com.busanit501.findmyfet.domain.Comment.class, com.busanit501.findmyfet.dto.CommentDTO.class)
                .addMappings(mapper -> {
                    mapper.map(src -> src.getPost().getId(), com.busanit501.findmyfet.dto.CommentDTO::setPostId);
                    mapper.map(src -> src.getUser().getUserId(), com.busanit501.findmyfet.dto.CommentDTO::setUserId);
                    mapper.map(src -> src.getUser().getName(), com.busanit501.findmyfet.dto.CommentDTO::setUserName);
                    mapper.map(src -> src.getUser().getLoginId(), com.busanit501.findmyfet.dto.CommentDTO::setLoginId);
                });

        return modelMapper;
    }

    @PersistenceContext
    private EntityManager entityManager;

    @Bean
    public JPAQueryFactory jpaQueryFactory() {
        return new JPAQueryFactory(entityManager);
    }
}