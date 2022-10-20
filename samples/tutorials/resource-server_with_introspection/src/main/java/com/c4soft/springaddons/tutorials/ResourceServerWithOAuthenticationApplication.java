package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
	}

	@EnableMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
	}

}
