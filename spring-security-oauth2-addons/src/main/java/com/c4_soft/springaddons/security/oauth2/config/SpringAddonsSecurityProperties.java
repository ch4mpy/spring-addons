package com.c4_soft.springaddons.security.oauth2.config;

import java.nio.charset.Charset;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import lombok.Data;

/**
 * Used to configure abstract web security-config {@link OidcServletApiSecurityConfig} and {@link OidcReactiveApiSecurityConfig}. Here are
 * defaults:
 *
 * <pre>
 * com.c4-soft.springaddons.security.anonymous-enabled=true
 * com.c4-soft.springaddons.security.authorities-claims=realm_access.roles
 * com.c4-soft.springaddons.security.authorities-prefix=
 * com.c4-soft.springaddons.security.authorities-uppercase=false
 * com.c4-soft.springaddons.security.cors[0].path=/**
 * com.c4-soft.springaddons.security.cors[0].allowed-origins=*
 * com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
 * com.c4-soft.springaddons.security.cors[0].allowedMethods=*
 * com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
 * com.c4-soft.springaddons.security.cors[0].exposedHeaders=*
 * com.c4-soft.springaddons.security.csrf-enabled=false
 * com.c4-soft.springaddons.security.permit-all=
 * com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=true
 * com.c4-soft.springaddons.security.statless-sessions=true
 * </pre>
 *
 * @author ch4mp
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SpringAddonsSecurityProperties {
	private String[] authoritiesClaims = { "realm_access.roles" };

	private String authoritiesPrefix = "";

	private boolean authoritiesUppercase = false;

	private CorsProperties[] cors = { new CorsProperties() };

	private boolean anonymousEnabled = true;

	private boolean csrfEnabled = false;

	private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**", "/favicon.ico" };

	private boolean redirectToLoginIfUnauthorizedOnRestrictedContent = false;

	private boolean statlessSessions = true;

	private String[] authorizationServerLocations = {};

	private Charset jsonTokenStringCharset;

	@Data
	public static class CorsProperties {
		private String path = "/**";
		private String[] allowedOrigins = { "*" };
		private String[] allowedMethods = { "*" };
		private String[] allowedHeaders = { "*" };
		private String[] exposedHeaders = { "*" };
	}

	public Stream<GrantedAuthority> getAuthorities(Map<String, Object> claims) {
		return Stream
				.of(authoritiesClaims)
				.flatMap(rolesPath -> getRoles(claims, rolesPath))
				.map(r -> authoritiesPrefix + (authoritiesUppercase ? r.toUpperCase() : r))
				.map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r));

	}

	private static Stream<String> getRoles(Map<String, Object> claims, String rolesPath) {
		final var claimsToWalk = rolesPath.split("\\.");
		var i = 0;
		var obj = Optional.of(claims);
		while (i++ < claimsToWalk.length) {
			final var claimName = claimsToWalk[i - 1];
			if (i == claimsToWalk.length) {
				return obj.map(o -> (JSONArray) o.get(claimName)).orElse(new JSONArray()).stream().map(Object::toString);
			}
			obj = obj.map(o -> (JSONObject) o.get(claimName));

		}
		return Stream.empty();
	}

}