package com.c4soft.springaddons.samples.bff.users;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Users API", version = "1.0.0"), security = { @SecurityRequirement(name = "OAuth2") })
public class RestApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(RestApiApplication.class, args);
	}

	@Configuration
	@EnableMethodSecurity
	public static class WebSecurityConfig {
	}
}
