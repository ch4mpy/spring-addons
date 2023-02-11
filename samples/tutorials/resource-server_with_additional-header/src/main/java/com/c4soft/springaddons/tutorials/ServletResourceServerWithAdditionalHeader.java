package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.HttpServletRequestSupport;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.HttpServletRequestSupport.InvalidHeaderException;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationFactory;

import lombok.Data;
import lombok.EqualsAndHashCode;

@SpringBootApplication
public class ServletResourceServerWithAdditionalHeader {

	public static void main(String[] args) {
		SpringApplication.run(ServletResourceServerWithAdditionalHeader.class, args);
	}

	@Configuration
	@EnableMethodSecurity
	public static class SecurityConfig {
		public static final String ID_TOKEN_HEADER_NAME = "X-ID-Token";

		@Bean
		OAuth2AuthenticationFactory authenticationFactory(
				Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
				JwtDecoder jwtDecoder) {
			return (accessBearerString, accessClaims) -> {
				try {
					final var authorities = authoritiesConverter.convert(accessClaims);
					final var idTokenString = HttpServletRequestSupport.getUniqueHeader(ID_TOKEN_HEADER_NAME);
					final var idToken = jwtDecoder.decode(idTokenString);

					return new MyAuth(authorities, accessBearerString, new OpenidClaimSet(accessClaims), idTokenString,
							new OpenidClaimSet(idToken.getClaims()));
				} catch (JwtException e) {
					throw new InvalidHeaderException(ID_TOKEN_HEADER_NAME);
				}
			};
		}

		@Bean
		ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			// @formatter:off
            return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                    .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
                    .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
                    .anyRequest().authenticated();
            // @formatter:on
		}

		@Data
		@EqualsAndHashCode(callSuper = true)
		public static class MyAuth extends OAuthentication<OpenidClaimSet> {
			private static final long serialVersionUID = 1734079415899000362L;
			private final String idTokenString;
			private final OpenidClaimSet idClaims;

			public MyAuth(Collection<? extends GrantedAuthority> authorities, String accessTokenString,
					OpenidClaimSet accessClaims, String idTokenString, OpenidClaimSet idClaims) {
				super(accessClaims, authorities, accessTokenString);
				this.idTokenString = idTokenString;
				this.idClaims = idClaims;
			}

		}
	}

}
