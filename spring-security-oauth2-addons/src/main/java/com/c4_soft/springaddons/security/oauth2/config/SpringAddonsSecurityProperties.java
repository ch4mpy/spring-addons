package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import lombok.Data;

/**
 * Here are defaults:
 *
 * <pre>
 * com.c4-soft.springaddons.security.anonymous-enabled=true
 * com.c4-soft.springaddons.security.authorities[0].authorization-server-location=https://dev-ch4mpy.eu.auth0.com/
 * com.c4-soft.springaddons.security.authorities[0].claims=realm_access.roles,permissions
 * com.c4-soft.springaddons.security.authorities[0].prefix=
 * com.c4-soft.springaddons.security.authorities[0].to-upper-case=false
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
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SpringAddonsSecurityProperties {

	private AuthoritiesMappingProperties[] authorities = {};

	private CorsProperties[] cors = { new CorsProperties() };

	private boolean anonymousEnabled = true;

	private boolean csrfEnabled = false;

	private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**", "/favicon.ico" };

	private boolean redirectToLoginIfUnauthorizedOnRestrictedContent = false;

	private boolean statlessSessions = true;

	@Data
	public static class CorsProperties {
		private String path = "/**";
		private String[] allowedOrigins = { "*" };
		private String[] allowedMethods = { "*" };
		private String[] allowedHeaders = { "*" };
		private String[] exposedHeaders = { "*" };
	}

	@Data
	public static class AuthoritiesMappingProperties {
		private String authorizationServerLocation;
		private String[] claims = { "realm_access.roles" };
		private String prefix = "";
		private boolean toUpperCase = false;

		public Stream<GrantedAuthority> mapAuthorities(Map<String, Object> token) {
			return Stream
					.of(claims)
					.flatMap(rolesPath -> getRoles(token, rolesPath))
					.map(r -> prefix + (toUpperCase ? r.toUpperCase() : r))
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

}