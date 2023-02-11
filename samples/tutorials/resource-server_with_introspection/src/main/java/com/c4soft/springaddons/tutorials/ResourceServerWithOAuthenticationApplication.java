package com.c4soft.springaddons.tutorials;

import java.util.List;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
	}

	@Configuration
	@EnableMethodSecurity
	public static class WebSecurityConfig {
	}

@Bean
OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter() {
    return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) ->
        new BearerTokenAuthentication(
        		authenticatedPrincipal,
        		new OAuth2AccessToken(TokenType.BEARER, introspectedToken, authenticatedPrincipal.getAttribute(IdTokenClaimNames.IAT), authenticatedPrincipal.getAttribute(IdTokenClaimNames.EXP)), 
        		((List<String>)authenticatedPrincipal.getAttribute("user-authorities")).stream().map(SimpleGrantedAuthority::new).toList());
}

}
