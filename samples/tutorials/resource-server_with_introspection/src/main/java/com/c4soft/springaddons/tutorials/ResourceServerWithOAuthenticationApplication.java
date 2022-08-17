package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public class WebSecurityConfig {
	}
}
