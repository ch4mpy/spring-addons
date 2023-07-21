package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ReactiveSpringAddonsOidcClientBeans.SpringAddonsWebSessionStore;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ReactiveSpringAddonsOidcClientBeans.WebSessionListener;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Work around the single tenancy nature of {@link OAuth2AuthenticationToken} and {@link InMemoryReactiveClientRegistrationRepository}: if a user authenticates
 * sequentially on several OP, his OAuth2AuthenticationToken will contain an {@link OAuth2User} corresponding only to the last OP he authenticated with. To work
 * around this limitation, this repository keeps an OAuth2User for each OP (issuer) and resolves the authorization client with the right Principal name for each
 * issuer.
 * </p>
 * <p>
 * This repo is also a session listener to keep track of all the (issuer, principalName) pairs and their associations with sessions (many to many relation).
 * This enables it to expose the required API for back-channel logout where a request is received to remove an authorized client based on its issuer and
 * Principal name but without a session token.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class SpringAddonsServerOAuth2AuthorizedClientRepository implements ServerOAuth2AuthorizedClientRepository, WebSessionListener {
	private static final String OAUTH2_USERS_KEY = "com.c4-soft.spring-addons.OAuth2.client.oauth2-users";
	private static final String AUTHORIZED_CLIENTS_KEY = "com.c4-soft.spring-addons.OAuth2.client.authorized-clients";

	private static final Map<UserId, Set<WebSession>> sessionsByuserId = new ConcurrentHashMap<>();
	private static final Map<String, Set<UserId>> userIdsBySessionId = new ConcurrentHashMap<>();

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private final SpringAddonsWebSessionStore webSessionStore;

	public SpringAddonsServerOAuth2AuthorizedClientRepository(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsWebSessionStore webSessionStore) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.webSessionStore = webSessionStore;
		this.webSessionStore.addWebSessionListener(this);
	}

	@Override
	public void sessionRemoved(String sessionId) {
		final var idsToUpdate = getUserIds(sessionId);
		for (var id : idsToUpdate) {
			setSessions(
					id.iss(),
					id.principalName(),
					new HashSet<>(getSessions(id.iss(), id.principalName()).stream().filter(s -> !(s.getId().equals(sessionId))).collect(Collectors.toSet())));
		}
		userIdsBySessionId.remove(sessionId);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId, Authentication auth, ServerWebExchange exchange) {
		return clientRegistrationRepository.findByRegistrationId(clientRegistrationId).flatMap(reg -> {
			final var issuer = reg.getProviderDetails().getIssuerUri();
			return exchange.getSession().flatMap(session -> loadAuthorizedClient(session, issuer, auth.getName()).map(ac -> (T) ac));
		});
	}

	public Mono<OAuth2AuthorizedClient> loadAuthorizedClient(WebSession session, String issuer, String principalName) {
		final var authorizedClients = getAuthorizedClients(session);
		final var client = authorizedClients.stream()
				.filter(
						ac -> Objects.equals(ac.getClientRegistration().getProviderDetails().getIssuerUri(), issuer)
								&& Objects.equals(ac.getPrincipalName(), principalName))
				.findAny().map(c -> {
					return Mono.just(c);
				}).orElse(Mono.empty());
		return client;
	}

	@Override
	public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication auth, ServerWebExchange exchange) {
		if (auth instanceof OAuth2LoginAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
			return exchange.getSession().map(session -> saveAuthorizedClient(session, authorizedClient, (OAuth2User) auth.getPrincipal())).then();
		}
		return Mono.empty();
	}

	private Mono<Void> saveAuthorizedClient(WebSession session, OAuth2AuthorizedClient authorizedClient, OAuth2User user) {
		final var issuer = authorizedClient.getClientRegistration().getProviderDetails().getIssuerUri();
		final var principalName = user.getName();

		final var oauth2Users = getOAuth2Users(session);
		if (oauth2Users.containsKey(issuer)) {
			removeAuthorizedClient(session, issuer, oauth2Users.get(issuer).getName());
		}
		oauth2Users.put(issuer, user);
		setOAuth2Users(session, oauth2Users);

		final var authorizedClients = getAuthorizedClients(session);
		authorizedClients.add(authorizedClient);
		setAuthorizedClients(session, authorizedClients);

		final var sessions = getSessions(issuer, principalName);
		if (!sessions.contains(session)) {
			sessions.add(session);
			setSessions(issuer, principalName, sessions);
		}

		final var userIds = getUserIds(session.getId());
		userIds.add(new UserId(issuer, principalName));
		setUserIds(session.getId(), userIds);

		return Mono.empty();
	}

	@Override
	public Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication auth, ServerWebExchange exchange) {
		if (auth instanceof OAuth2LoginAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
			return clientRegistrationRepository.findByRegistrationId(clientRegistrationId).map(reg -> {
				final var issuer = reg.getProviderDetails().getIssuerUri();
				return exchange.getSession().map(session -> removeAuthorizedClient(session, issuer, auth.getName()));
			}).then();
		}
		return Mono.empty();
	}

	public Mono<Void> removeAuthorizedClient(WebSession session, String issuer, String principalName) {
		final var allAuthorizedClients = getAuthorizedClients(session);
		final var authorizedClientsToRemove = allAuthorizedClients.stream()
				.filter(
						ac -> Objects.equals(ac.getClientRegistration().getProviderDetails().getIssuerUri(), issuer)
								&& Objects.equals(ac.getPrincipalName(), principalName))
				.collect(Collectors.toSet());
		allAuthorizedClients.removeAll(authorizedClientsToRemove);
		setAuthorizedClients(session, allAuthorizedClients);

		final var oauth2Users = getOAuth2Users(session);
		if (oauth2Users.containsKey(issuer)) {
			oauth2Users.remove(issuer);
			setOAuth2Users(session, oauth2Users);
		}

		final var sessions = getSessions(issuer, principalName);
		if (sessions.contains(session)) {
			sessions.remove(session);
			setSessions(issuer, principalName, sessions);
		}

		final var userIds = getUserIds(session.getId());
		userIds.remove(new UserId(issuer, principalName));

		return Mono.empty();
	}

	/**
	 * Removes an authorized client and returns a list of sessions to invalidate (those for which the current user has no more authorized client after this one
	 * was removed)
	 *
	 * @param  issuer        OP issuer URI
	 * @param  principalName current user name for this OP
	 * @return               the list of user sessions for which this authorized client was the last one
	 */
	public Flux<WebSession> removeAuthorizedClients(String issuer, String principalName) {
		final var sessions = getSessions(issuer, principalName);

		for (var session : sessions) {
			removeAuthorizedClient(session, issuer, principalName);
		}

		return Flux.fromStream(sessions.stream().filter(s -> {
			return getAuthorizedClients(s).stream()
					.filter(
							authorizedClient -> authorizedClient.getClientRegistration().getProviderDetails().getIssuerUri().equals(issuer)
									&& authorizedClient.getPrincipalName().equals(principalName))
					.count() < 1;
		}));
	}

	@SuppressWarnings("unchecked")
	private Set<OAuth2AuthorizedClient> getAuthorizedClients(WebSession session) {
		final var sessionAuthorizedClients = (Set<OAuth2AuthorizedClient>) session.getAttribute(AUTHORIZED_CLIENTS_KEY);
		return sessionAuthorizedClients == null ? new HashSet<>() : sessionAuthorizedClients;
	}

	private void setAuthorizedClients(WebSession session, Set<OAuth2AuthorizedClient> sessionAuthorizedClients) {
		session.getAttributes().put(AUTHORIZED_CLIENTS_KEY, sessionAuthorizedClients);
	}

	public Map<String, OAuth2User> getOAuth2UsersBySession(WebSession session) {
		if (session == null) {
			return null;
		}
		return Collections.unmodifiableMap(getOAuth2Users(session));
	}

	@SuppressWarnings("unchecked")
	private Map<String, OAuth2User> getOAuth2Users(WebSession s) {
		final var sessionOauth2UsersByIssuer = (Map<String, OAuth2User>) s.getAttribute(OAUTH2_USERS_KEY);
		return sessionOauth2UsersByIssuer == null ? new ConcurrentHashMap<String, OAuth2User>() : sessionOauth2UsersByIssuer;
	}

	private void setOAuth2Users(WebSession s, Map<String, OAuth2User> sessionOauth2UsersByIssuer) {
		s.getAttributes().put(OAUTH2_USERS_KEY, sessionOauth2UsersByIssuer);
	}

	private Set<WebSession> getSessions(String issuer, String principalName) {
		return sessionsByuserId.getOrDefault(new UserId(issuer, principalName), new HashSet<>());
	}

	private void setSessions(String issuer, String principalName, Set<WebSession> sessions) {
		if (sessions == null || sessions.isEmpty()) {
			sessionsByuserId.remove(new UserId(issuer, principalName));
		} else {
			sessionsByuserId.put(new UserId(issuer, principalName), sessions);
		}
	}

	private Set<UserId> getUserIds(String sessionId) {
		return userIdsBySessionId.getOrDefault(sessionId, new HashSet<>());
	}

	private void setUserIds(String sessionId, Set<UserId> userIds) {
		if (userIds == null || userIds.isEmpty()) {
			userIdsBySessionId.remove(sessionId);
		} else {
			userIdsBySessionId.put(sessionId, userIds);
		}
	}

	private static record UserId(String iss, String principalName) {
	}
}
