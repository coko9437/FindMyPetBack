package com.busanit501.findmyfet.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    // application.properties에 설정한 파일 업로드 경로를 주입받습니다.
//    @Value("${upload.path}")
//    private String uploadPath;
    @Value("${upload.dir}")
    private String uploadDir;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // '/upload/**' URL 패턴으로 요청이 오면
        registry.addResourceHandler("/upload/**")
                // 로컬 디스크의 'file:///C:/Users/사용자명/upload/' 경로와 매핑합니다.
                .addResourceLocations("file:///" + uploadDir );
    }
}