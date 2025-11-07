package com.busanit501.findmyfet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EntityScan("com.busanit501.findmyfet.domain")
@EnableJpaAuditing // JPA Auditing 기능 사용 어노테이션
@SpringBootApplication
public class FindMyFetApplication {

    public static void main(String[] args) {
        SpringApplication.run(FindMyFetApplication.class, args);
    }

}
