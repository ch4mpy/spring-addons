package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
    }

    @Configuration
    @EnableMethodSecurity
    public static class WebSecurityConfig {
    }

}
