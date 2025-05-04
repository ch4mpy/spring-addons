package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

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

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    resolver.resolve(request);

    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri);
    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
        postLoginFailureUri);
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

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    resolver.resolve(request);

    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri);
    verify(session).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
        postLoginFailureUri);
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithoutAnAuthorityAndRequestPostLoginSuccessRedirectUriHeaderHasAnAuthority_whenResolve_thenThrows() {
    final var postLoginSuccessUri = URI.create("https://localhost/ui/account");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getSession()).thenReturn(session);
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri.toString());

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidRedirectionUriException.class, () -> resolver.resolve(request));

    verify(session, never()).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE,
        postLoginSuccessUri);
  }

  @Test
  void givenDefaultPostLoginAllowedUriPatternsForClientUriWithoutAnAuthorityAndRequestPostLoginFailureRedirectUriHeaderHasAnAuthority_whenResolve_thenThrows() {
    final var postLoginSuccessUri = URI.create("/ui/account");
    final var postLoginFailureUri = URI.create("https://localhost/ui/error");
    when(addonsClientProperties.getPostLoginAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLoginRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getSession()).thenReturn(session);
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
        .thenReturn(postLoginSuccessUri.toString());
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
        .thenReturn(postLoginFailureUri.toString());

    final var resolver = new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsClientProperties);
    assertThrows(InvalidRedirectionUriException.class, () -> resolver.resolve(request));

    verify(session, never()).setAttribute(
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE,
        postLoginFailureUri);
  }
}
