package com.c4soft.springaddons.tutorials;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;

public class HttpSessionSupport {
	private static final String SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID = "c4.spring-addons.identitiesByRegistrationId";

	public static HttpSession getSession() {
		ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
		HttpSession session = attr.getRequest().getSession();
		return session;
	}

	public static Map<String, Identity> getIdentitiesByRegistrationId() {
		final var session = getSession();
		@SuppressWarnings("unchecked")
		final var identitiesByRegistrationId = (Map<String, Identity>) session.getAttribute(SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID);
		return identitiesByRegistrationId == null ? Map.of() : identitiesByRegistrationId;
	}

	static Map<String, Identity> setIdentitiesByRegistrationId(Map<String, Identity> identitiesByRegistrationId) {
		final var session = getSession();
		final var updated = Collections.unmodifiableMap(identitiesByRegistrationId);
		session.setAttribute(SESSION_KEY_C4_SPRING_ADDONS_IDENTITIES_BY_REGISTRATION_ID, updated);
		return updated;
	}

	public static void invalidate() {
		getSession().invalidate();
	}

	public static Map<String, Identity> addIdentity(String registrationId, String subject, String idToken) {
		final var identity = new Identity(subject, idToken);
		final var identitiesByRegistrationId = new HashMap<>(getIdentitiesByRegistrationId());
		identitiesByRegistrationId.put(registrationId, identity);
		return setIdentitiesByRegistrationId(identitiesByRegistrationId);
	}

	public static Map<String, Identity> removeIdentity(String registrationId) {
		final var identitiesByRegistrationId = new HashMap<>(getIdentitiesByRegistrationId());
		identitiesByRegistrationId.remove(registrationId);
		return setIdentitiesByRegistrationId(identitiesByRegistrationId);
	}

	public static String getUserSubject(String clientRegistrationId) {
		return Optional.ofNullable(getIdentitiesByRegistrationId().get(clientRegistrationId)).map(Identity::getSubject).orElse(null);
	}

	public static String getUserIdToken(String clientRegistrationId) {
		return Optional.ofNullable(getIdentitiesByRegistrationId().get(clientRegistrationId)).map(Identity::getIdToken).orElse(null);
	}

	@Data
	@RequiredArgsConstructor
	public static class Identity implements Serializable {
		private static final long serialVersionUID = 6716380421507423140L;

		private final String subject;
		private final String idToken;
	}
}