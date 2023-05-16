package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@SecurityScheme(
		name = "authorization-code",
		type = SecuritySchemeType.OAUTH2,
		flows = @OAuthFlows(
				authorizationCode = @OAuthFlow(
						authorizationUrl = "https://localhost:8443/realms/master/protocol/openid-connect/auth",
						tokenUrl = "https://localhost:8443/realms/master/protocol/openid-connect/token",
						scopes = { @OAuthScope(name = "openid"), @OAuthScope(name = "profile") })))
@SpringBootApplication
public class ResourceServerMultitenantDynamicApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerMultitenantDynamicApplication.class, args);
	}

}
