package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.MappingMatch;

@ExtendWith(MockitoExtension.class)
class SpringAddonsOAuth2AuthorizationRequestResolverTest {

  @Mock
  OAuth2ClientProperties bootClientProperties;

  @Mock
  ClientRegistrationRepository clientRegistrationRepository;

  @Mock
  SpringAddonsOidcClientProperties addonsClientProperties;

  @Mock
  HttpSession session;

  @Mock
  HttpServletRequest request;

  @Test
  void givenNeitherClientUriNorDefaultPostLoginAllowedUriPatternsNorPostLoginRedirectUriHaHaveAnAuthority_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));

    assertDoesNotThrow(() -> new SpringAddonsOAuth2AuthorizationRequestResolver(
        bootClientProperties, clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenClientUriHasAnAuthorityButPostLoginRedirectUridoesNot_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));

    assertDoesNotThrow(() -> new SpringAddonsOAuth2AuthorizationRequestResolver(
        bootClientProperties, clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenNeitherClientUriNorDefaultPostLoginAllowedUriPatternsHaveAnAuthorityButConfiguredPostLoginRedirectUriHasOne_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenThrows() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://localhost:8080/ui/"));

    assertThrows(MisconfiguredPostLoginUriException.class,
        () -> new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
            clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenClientUriAndConfiguredPostLoginRedirectUriHaveSameAuthority_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://localhost:8080/ui/"));

    assertDoesNotThrow(() -> new SpringAddonsOAuth2AuthorizationRequestResolver(
        bootClientProperties, clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenClientUriAndConfiguredPostLoginRedirectUriHaveDifferentAuthorities_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenThrows() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("http://localhost:4200"));

    assertThrows(MisconfiguredPostLoginUriException.class,
        () -> new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
            clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenPostLoginAllowedUriPatternAllowsAnySubDomainAndConfiguredPostLoginRedirectUriHasHostInDomain_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns()).thenReturn(List
        .of(Pattern.compile(".*\\.chose\\.pf(/.*)?"), Pattern.compile(".*\\.machin\\.pf(/.*)?")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://machin.chose.pf"));

    assertDoesNotThrow(() -> new SpringAddonsOAuth2AuthorizationRequestResolver(
        bootClientProperties, clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenPostLoginAllowedUriPatternAllowsAnySubDomainAndConfiguredPostLoginRedirectUriHasHostInAnotherDomain_whenBuildSpringAddonsOAuth2AuthorizationRequestResolver_thenThrows() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns()).thenReturn(List
        .of(Pattern.compile(".*\\.chose\\.pf(/.*)?"), Pattern.compile(".*\\.machin\\.pf(/.*)?")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://machinchose.pf/"));

    assertThrows(MisconfiguredPostLoginUriException.class,
        () -> new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
            clientRegistrationRepository, addonsClientProperties));
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithAnAuthorityAndRequestPostLoginRedirectUriHeaderHasNoAuthority_whenResolve_thenDoesNotThrow() {
    final var postLoginSuccessUri = URI.create("/ui/account");
    final var postLoginFailureUri = URI.create("/ui/error");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("https://localhost(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://localhost/ui/"));
    when(request.getSession()).thenReturn(session);
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri.toString());
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
        .thenReturn(postLoginFailureUri.toString());
    final var mapping = mock(HttpServletMapping.class);
    when(request.getHttpServletMapping()).thenReturn(mapping);
    when(mapping.getMappingMatch()).thenReturn(MappingMatch.EXACT);
    when(request.getContextPath()).thenReturn("/");
    when(request.getRequestURI()).thenReturn("/");

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    resolver.resolve(request);

    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri.toString());
    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
        postLoginFailureUri.toString());
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithAnAuthorityAndRequestPostLoginRedirectUriParamHasNoAuthority_whenResolve_thenDoesNotThrow() {
    final var postLoginSuccessUri = URI.create("/ui/account");
    final var postLoginFailureUri = URI.create("/ui/error");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("https://localhost(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri())
        .thenReturn(URI.create("https://localhost/ui/"));
    when(request.getSession()).thenReturn(session);
    when(request
        .getParameterValues(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM))
            .thenReturn(new String[] {postLoginSuccessUri.toString()});
    when(request
        .getParameterValues(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM))
            .thenReturn(new String[] {postLoginFailureUri.toString()});
    final var mapping = mock(HttpServletMapping.class);
    when(request.getHttpServletMapping()).thenReturn(mapping);
    when(mapping.getMappingMatch()).thenReturn(MappingMatch.EXACT);
    when(request.getContextPath()).thenReturn("/");
    when(request.getRequestURI()).thenReturn("/");

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    resolver.resolve(request);

    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri.toString());
    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
        postLoginFailureUri.toString());
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithoutAnAuthorityAndRequestPostLoginSuccessRedirectUriHeaderHasAnAuthority_whenResolve_thenThrows() {
    final var postLoginSuccessUri = URI.create("https://localhost/ui/account");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri.toString());

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidPostLoginUriException.class, () -> resolver.resolve(request));

    // a refused URI leaves the session untouched (not even opened)
    verify(request, never()).getSession();
    verify(request, never()).getSession(true);
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithoutAnAuthorityAndRequestPostLoginFailureRedirectUriHeaderHasAnAuthority_whenResolve_thenThrows() {
    final var postLoginSuccessUri = URI.create("/ui/account");
    final var postLoginFailureUri = URI.create("https://localhost/ui/error");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri.toString());
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
        .thenReturn(postLoginFailureUri.toString());

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidPostLoginUriException.class, () -> resolver.resolve(request));

    // the valid success URI is not stored either: both are checked before anything is stored
    verify(request, never()).getSession();
    verify(request, never()).getSession(true);
    verify(session, never()).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri.toString());
  }

  @Test
  void givenNoPostLoginUriInRequest_whenResolve_thenNoSessionIsOpened() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    final var mapping = mock(HttpServletMapping.class);
    when(request.getHttpServletMapping()).thenReturn(mapping);
    when(mapping.getMappingMatch()).thenReturn(MappingMatch.EXACT);
    when(request.getContextPath()).thenReturn("/");
    when(request.getRequestURI()).thenReturn("/");

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    resolver.resolve(request);

    verify(request, never()).getSession();
    verify(request, never()).getSession(true);
  }

  @Test
  void givenPathOnlyAllowedUriPatternAndRequestPostLoginSuccessRedirectUriHeaderIsSchemeRelative_whenResolve_thenThrows() {
    final var postLoginSuccessUri = "//evil.com/ui/account";
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri);

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidPostLoginUriException.class, () -> resolver.resolve(request));

    verify(request, never()).getSession();
    verify(request, never()).getSession(true);
  }

  @Test
  void givenPathOnlyAllowedUriPatternAndRequestPostLoginFailureRedirectUriParamIsSchemeRelative_whenResolve_thenThrows() {
    final var postLoginFailureUri = "//evil.com/ui/error";
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getParameterValues(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM)).thenReturn(null);
    when(request.getParameterValues(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM))
            .thenReturn(new String[] {postLoginFailureUri});

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidPostLoginUriException.class, () -> resolver.resolve(request));

    verify(request, never()).getSession();
    verify(request, never()).getSession(true);
  }

  @Test
  void givenRequestPostLoginSuccessRedirectUriHeaderIsMalformed_whenResolve_thenThrowsInvalidRedirectionUri() {
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn("/\\evil.com");

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidPostLoginUriException.class, () -> resolver.resolve(request));
  }

  @Test
  void givenContextPathAndClientUriWithoutPath_whenResolve_thenContextPathIsKept() {
    assertThat(redirectUri("https://host", "/gateway"))
        .isEqualTo("https://host/gateway/login/oauth2/code/reg");
  }

  @Test
  void givenContextPathAndClientUriEndingWithIt_whenResolve_thenContextPathIsNotDuplicated() {
    assertThat(redirectUri("https://host/gateway", "/gateway"))
        .isEqualTo("https://host/gateway/login/oauth2/code/reg");
  }

  @Test
  void givenNoContextPathAndClientUriWithPath_whenResolve_thenRedirectUriIsRebasedOnClientUri() {
    assertThat(redirectUri("https://host/bff", ""))
        .isEqualTo("https://host/bff/login/oauth2/code/reg");
  }

  @Test
  void givenAllowedHeaderAndRefusedParam_whenResolve_thenHeaderWinsAndIsStored() {
    final var bootProperties = new OAuth2ClientProperties();
    bootProperties.getRegistration().put("reg", new OAuth2ClientProperties.Registration());
    final var registrations = new InMemoryClientRegistrationRepository(ClientRegistration
        .withRegistrationId("reg").clientId("client-id")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://op/authorize").tokenUri("https://op/token").build());
    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/reg");
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        "/ui/account");
    request.addParameter(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM,
        "https://evil.com/ui/account");

    final var actual = new SpringAddonsOAuth2AuthorizationRequestResolver(bootProperties,
        registrations, new SpringAddonsOidcClientProperties()).resolve(request);

    assertThat(actual).isNotNull();
    assertThat(request.getSession(false).getAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE))
            .isEqualTo("/ui/account");
  }

  private static String redirectUri(String clientUri, String contextPath) {
    final var bootProperties = new OAuth2ClientProperties();
    bootProperties.getRegistration().put("reg", new OAuth2ClientProperties.Registration());
    final var registrations = new InMemoryClientRegistrationRepository(ClientRegistration
        .withRegistrationId("reg").clientId("client-id")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://op/authorize").tokenUri("https://op/token").build());
    final var addonsProperties = new SpringAddonsOidcClientProperties();
    addonsProperties.setClientUri(Optional.of(URI.create(clientUri)));
    final var request =
        new MockHttpServletRequest("GET", contextPath + "/oauth2/authorization/reg");
    request.setContextPath(contextPath);

    final var actual =
        new SpringAddonsOAuth2AuthorizationRequestResolver(bootProperties, registrations,
            addonsProperties).resolve(request);

    assertThat(actual).isNotNull();
    return actual.getRedirectUri();
  }
}
