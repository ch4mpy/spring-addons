package com.c4soft.springaddons.showcase;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimNames;

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any Token Introspection endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
@FrameworkEndpoint
@RequestMapping("/introspect")
class IntrospectEndpoint {
	TokenStore tokenStore;

	public IntrospectEndpoint(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@PostMapping
	@ResponseBody
	public Map<String, Object> introspect(@RequestParam("token") String token) {
		final OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);
		final Map<String, Object> attributes = new HashMap<>();
		if (accessToken == null || accessToken.isExpired()) {
			attributes.put(IntrospectionClaimNames.ACTIVE.value, false);
			return attributes;
		}

		final OAuth2Authentication authentication = tokenStore.readAuthentication(token);

		attributes.put(IntrospectionClaimNames.ACTIVE.value, true);
		attributes.put(IntrospectionClaimNames.EXPIRES_AT.value, accessToken.getExpiration().getTime() / 1000L);
		if(accessToken.getScope().contains("granted-authority-scopes")) {
			attributes.remove("authorities");
			attributes.put(
					IntrospectionClaimNames.SCOPE.value,
					authentication.getAuthorities().stream()
						.map(GrantedAuthority::getAuthority)
						.collect(Collectors.joining(" ")));
		} else if (!accessToken.getScope().contains("none")){
			final Set<String> scopes = accessToken.getScope();
			attributes.put(IntrospectionClaimNames.SCOPE.value, scopes.stream().collect(Collectors.joining(" ")));
			attributes.put("authorities", authentication.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.filter(a -> scopes.contains(a.split(":")[0]))
					.collect(Collectors.toSet()));
		}
		attributes.put(IntrospectionClaimNames.SUBJECT.value, authentication.getName());


		return attributes;
	}
}