package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpSession;

public class MultiTenantOAuth2PrincipalSupport {
	private static final String OAUTH2_USERS_KEY = "com.c4-soft.spring-addons.oauth2.client.principal-by-client-registration-id";

	@SuppressWarnings("unchecked")
	public static Map<String, Authentication> getAuthenticationsByClientRegistrationId(HttpSession session) {
		return Optional.ofNullable((Map<String, Authentication>) session.getAttribute(OAUTH2_USERS_KEY)).orElse(new HashMap<String, Authentication>());
	}

	public static Optional<Authentication> getAuthentication(HttpSession session, String clientRegistrationId) {
		return Optional.ofNullable(getAuthenticationsByClientRegistrationId(session).get(clientRegistrationId));
	}

	public static synchronized void add(HttpSession session, String clientRegistrationId, Authentication auth) {
		final var identities = getAuthenticationsByClientRegistrationId(session);
		identities.put(clientRegistrationId, auth);
		session.setAttribute(OAUTH2_USERS_KEY, identities);
	}

	public static synchronized void remove(HttpSession session, String clientRegistrationId) {
		final var identities = getAuthenticationsByClientRegistrationId(session);
		identities.remove(clientRegistrationId);
		session.setAttribute(OAUTH2_USERS_KEY, identities);
	}
}