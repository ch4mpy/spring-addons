package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationFactory;

@SpringBootApplication
public class ResourceServerWithUiApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerWithUiApplication.class, args);
	}

	@EnableMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
		@Bean
		OAuth2AuthenticationFactory authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
			return (bearerString, claims) -> new OAuthentication<>(new OpenidClaimSet(claims), authoritiesConverter.convert(claims), bearerString);
		}

		/**
		 * A default SecurityFilterChain is already defined by spring-addons-webmvc-jwt-resource-server to secure all API endpoints (actuator and
		 * REST controllers)
		 *
		 * @param  http
		 * @param  serverProperties
		 * @return                  an additional security filter-chain for UI elements (with OAuth2 login)
		 * @throws Exception
		 */
		@Order(Ordered.HIGHEST_PRECEDENCE)
		@Bean
		SecurityFilterChain uiFilterChain(
				HttpSecurity http,
				ServerProperties serverProperties,
				Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter)
				throws Exception {
			boolean isSsl = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();

		// @formatter:off
        http.securityMatcher(new OrRequestMatcher(
                // you might want to add path to your UI elements instead
                new AntPathRequestMatcher("/swagger-ui/**"),
                // those two are required to access Spring generated login page
                // and OAuth2 client callback endpoints
                new AntPathRequestMatcher("/login/**"),
                new AntPathRequestMatcher("/oauth2/**")));

        http.oauth2Login()
            .loginPage("%s://localhost:%d/oauth2/authorization/spring-addons-public".formatted(isSsl ? "https" : "http", serverProperties.getPort()) )
            .defaultSuccessUrl("%s://localhost:%d/swagger-ui/index.html".formatted(isSsl ? "https" : "http", serverProperties.getPort()), true)
            .userInfoEndpoint().userAuthoritiesMapper((authorities) -> {
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                authorities.forEach(authority -> {
                    if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                        mappedAuthorities.addAll(authoritiesConverter.convert(oidcUserAuthority.getIdToken().getClaims()));

                    } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                        mappedAuthorities.addAll(authoritiesConverter.convert(oauth2UserAuthority.getAttributes()));

                    }
                });

                return mappedAuthorities;
            });

        http.authorizeHttpRequests()
                .requestMatchers("/login/**").permitAll()
                .requestMatchers("/oauth2/**").permitAll()
                .anyRequest().authenticated();
        // @formatter:on

			// If SSL enabled, disable http (https only)
			if (isSsl) {
				http.requiresChannel().anyRequest().requiresSecure();
			} else {
				http.requiresChannel().anyRequest().requiresInsecure();
			}

			// compared to API filter-chain:
			// - sessions and CSRF protection are left enabled
			// - unauthorized requests to secured resources will be redirected to login (302 to login is Spring's default response when access is
			// denied)

			return http.build();
		}
	}

}
