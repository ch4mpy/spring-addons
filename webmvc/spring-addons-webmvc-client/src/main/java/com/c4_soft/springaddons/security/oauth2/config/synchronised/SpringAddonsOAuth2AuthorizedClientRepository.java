package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.nimbusds.jwt.JWTClaimNames;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import lombok.Data;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Work around the single tenancy nature of {@link OAuth2AuthenticationToken}
 * and {@link InMemoryReactiveClientRegistrationRepository}: if a user
 * authenticates sequentially on several OP, his OAuth2AuthenticationToken will
 * contain an {@link OAuth2User} corresponding only to the last OP he
 * authenticated with. To work around this limitation, this repository keeps an
 * OAuth2User for each OP (issuer) and resolves the authorization client with
 * the right subject for each issuer.
 * </p>
 * <p>
 * This repo is also a session listener to keep track of all the (issuer,
 * subject) pairs and their associations with sessions (many to many relation).
 * This enables it to expose the required API for back-channel logout where a
 * request is received to remove an authorized client based on its issuer and
 * subject but without a session token.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 *
 */
@RequiredArgsConstructor
public class SpringAddonsOAuth2AuthorizedClientRepository
        implements OAuth2AuthorizedClientRepository, HttpSessionListener, HttpSessionIdListener {
    private static final String OAUTH2_USERS_KEY = "com.c4-soft.spring-addons.OAuth2.client.oauth2-users";
    private static final String AUTHORIZED_CLIENTS_KEY = "com.c4-soft.spring-addons.OAuth2.client.authorized-clients";

    private static final Map<UserId, Set<HttpSession>> sessionsByuserId = new ConcurrentHashMap<>();
    private static final Map<String, Set<UserId>> userIdsBySessionId = new ConcurrentHashMap<>();

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        if (userIdsBySessionId.containsKey(oldSessionId)) {
            userIdsBySessionId.put(event.getSession().getId(), userIdsBySessionId.get(oldSessionId));
            userIdsBySessionId.remove(oldSessionId);
        }
    }

    @Override
    public void sessionCreated(HttpSessionEvent se) {
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        final var idsToUpdate = getUserIds(se.getSession().getId());
        for (var id : idsToUpdate) {
            setSessions(id.getIss(), id.getSub(), new HashSet<>(getSessions(id.getIss(), id.getSub()).stream()
                    .filter(s -> !(s.getId().equals(se.getSession().getId()))).collect(Collectors.toSet())));
        }
        userIdsBySessionId.remove(se.getSession().getId());
    }

    private Optional<String> getUserSubject(HttpSession session, String issuer) {
        final var oauth2Users = getOAuth2Users(session);
        return Optional.ofNullable(oauth2Users.get(issuer)).map(u -> u.getAttribute(JWTClaimNames.SUBJECT));
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
            Authentication auth, HttpServletRequest request) {
        final var issuer = clientRegistrationRepository.findByRegistrationId(clientRegistrationId).getProviderDetails()
                .getIssuerUri();
        final var subject = getUserSubject(request.getSession(), issuer).orElse(auth.getName());

        return (T) loadAuthorizedClient(request.getSession(), issuer, subject);
    }

    public OAuth2AuthorizedClient loadAuthorizedClient(HttpSession session, String issuer, String subject) {
        final var authorizedClients = getAuthorizedClients(session);
        return authorizedClients.stream()
                .filter(ac -> Objects.equals(ac.getClientRegistration().getProviderDetails().getIssuerUri(), issuer)
                        && Objects.equals(ac.getPrincipalName(), subject))
                .findAny().orElse(null);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication auth,
            HttpServletRequest request, HttpServletResponse response) {
        if (auth instanceof OAuth2LoginAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
            saveAuthorizedClient(request.getSession(), authorizedClient, (OAuth2User) auth.getPrincipal());
        }
    }

    private void saveAuthorizedClient(HttpSession session, OAuth2AuthorizedClient authorizedClient, OAuth2User user) {
        final var issuer = authorizedClient.getClientRegistration().getProviderDetails().getIssuerUri();
        final var subject = user.getAttributes().get(JWTClaimNames.SUBJECT).toString();

        final var oauth2Users = getOAuth2Users(session);
        if (oauth2Users.containsKey(issuer)) {
            removeAuthorizedClient(session, issuer, oauth2Users.get(issuer).getName());
        }
        oauth2Users.put(issuer, user);
        setOAuth2Users(session, oauth2Users);

        final var authorizedClients = getAuthorizedClients(session);
        authorizedClients.add(authorizedClient);
        setAuthorizedClients(session, authorizedClients);

        final var sessions = getSessions(issuer, subject);
        if (!sessions.contains(session)) {
            sessions.add(session);
            setSessions(issuer, subject, sessions);
        }

        final var userIds = getUserIds(session.getId());
        userIds.add(new UserId(issuer, subject));
        setUserIds(session.getId(), userIds);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, Authentication auth, HttpServletRequest request,
            HttpServletResponse response) {
        if (auth instanceof OAuth2LoginAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
            final var issuer = clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
                    .getProviderDetails()
                    .getIssuerUri();
            final var subject = getUserSubject(request.getSession(), issuer).orElse(auth.getName());

            removeAuthorizedClient(request.getSession(), issuer, subject);
        }
    }

    public void removeAuthorizedClient(HttpSession session, String issuer, String subject) {
        final var allAuthorizedClients = getAuthorizedClients(session);
        final var authorizedClientsToRemove = allAuthorizedClients.stream()
                .filter(ac -> Objects.equals(ac.getClientRegistration().getProviderDetails().getIssuerUri(), issuer)
                        && Objects.equals(ac.getPrincipalName(), subject))
                .collect(Collectors.toSet());
        allAuthorizedClients.removeAll(authorizedClientsToRemove);
        setAuthorizedClients(session, allAuthorizedClients);

        final var oauth2Users = getOAuth2Users(session);
        if (oauth2Users.containsKey(issuer)) {
            oauth2Users.remove(issuer);
            setOAuth2Users(session, oauth2Users);
        }

        final var sessions = getSessions(issuer, subject);
        if (sessions.contains(session)) {
            sessions.remove(session);
            setSessions(issuer, subject, sessions);
        }

        final var userIds = getUserIds(session.getId());
        userIds.remove(new UserId(issuer, subject));
    }

    /**
     * Removes an authorized client and returns a list of sessions to invalidate
     * (those for which the current user has no more authorized client after this
     * one was removed)
     *
     * @param issuer  OP issuer URI
     * @param subject current user subject for this OP
     * @return the list of user sessions for which this authorized client was the
     *         last one
     */
    public Collection<HttpSession> removeAuthorizedClients(String issuer, String subject) {
        final var sessions = getSessions(issuer, subject);

        final var sessionsToInvalidate = sessions.stream().filter(s -> {
            return getAuthorizedClients(s).stream()
                    .filter(authorizedClient -> authorizedClient.getClientRegistration().getProviderDetails()
                            .getIssuerUri().equals(issuer)
                            && authorizedClient.getPrincipalName().equals(subject))
                    .count() < 1;
        }).toList();

        for (var session : sessions) {
            removeAuthorizedClient(session, issuer, subject);
        }

        return sessionsToInvalidate;
    }

    @SuppressWarnings("unchecked")
    private Set<OAuth2AuthorizedClient> getAuthorizedClients(HttpSession session) {
        final var sessionAuthorizedClients = (Set<OAuth2AuthorizedClient>) session.getAttribute(AUTHORIZED_CLIENTS_KEY);
        return sessionAuthorizedClients == null ? new HashSet<>() : sessionAuthorizedClients;
    }

    private void setAuthorizedClients(HttpSession session, Set<OAuth2AuthorizedClient> sessionAuthorizedClients) {
        session.setAttribute(AUTHORIZED_CLIENTS_KEY, sessionAuthorizedClients);
    }

    public Map<String, OAuth2User> getOAuth2UsersBySession(HttpSession session) {
        if (session == null) {
            return null;
        }
        return Collections.unmodifiableMap(getOAuth2Users(session));
    }

    @SuppressWarnings("unchecked")
    private Map<String, OAuth2User> getOAuth2Users(HttpSession s) {
        final var sessionOauth2UsersByIssuer = (Map<String, OAuth2User>) s.getAttribute(OAUTH2_USERS_KEY);
        return sessionOauth2UsersByIssuer == null ? new ConcurrentHashMap<String, OAuth2User>()
                : sessionOauth2UsersByIssuer;
    }

    private void setOAuth2Users(HttpSession s, Map<String, OAuth2User> sessionOauth2UsersByIssuer) {
        s.setAttribute(OAUTH2_USERS_KEY, sessionOauth2UsersByIssuer);
    }

    private Set<HttpSession> getSessions(String issuer, String subject) {
        return sessionsByuserId.getOrDefault(new UserId(issuer, subject), new HashSet<>());
    }

    private void setSessions(String issuer, String subject, Set<HttpSession> sessions) {
        if (sessions == null || sessions.isEmpty()) {
            sessionsByuserId.remove(new UserId(issuer, subject));
        } else {
            sessionsByuserId.put(new UserId(issuer, subject), sessions);
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

    @Data
    @RequiredArgsConstructor
    private static final class UserId {
        private final String iss;
        private final String sub;
    }
}
