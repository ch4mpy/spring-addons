package com.c4soft.springaddons.showcase;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import com.c4soft.oauth2.rfc7519.JwtRegisteredClaimNames;

class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
	@Override
	public Map<String, ?> convertUserAuthentication(Authentication authentication) {
		@SuppressWarnings("unchecked")
		final Map<String, Object> details = (Map<String, Object>) authentication.getDetails();

		final Map<String, Object> authClaims = new LinkedHashMap<String, Object>(details);
		authClaims.put(JwtRegisteredClaimNames.SUBJECT.value, authentication.getName());

		final Set<String> scopes = details.containsKey("scope")
				? Stream.of(details.get("scope").toString().split(" ")).collect(Collectors.toSet())
				: Collections.emptySet();

		final var scopedAuthorities = authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.filter(authority -> scopes.contains(authority.split(":")[0]))
				.collect(Collectors.toSet());

		if (scopedAuthorities.size() > 0) {
			authClaims.put(AUTHORITIES, scopedAuthorities);
		}

		return authClaims;
	}
}