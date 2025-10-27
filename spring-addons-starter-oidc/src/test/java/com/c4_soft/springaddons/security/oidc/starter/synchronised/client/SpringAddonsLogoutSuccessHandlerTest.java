package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.MisconfiguredPostLogoutUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.OAuth2RedirectionProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
class SpringAddonsLogoutSuccessHandlerTest {

  @Mock
  LogoutRequestUriBuilder uriBuilder;

  @Mock
  ClientRegistrationRepository clientRegistrationRepository;

  OAuth2RedirectionProperties oauth2Redirections = new OAuth2RedirectionProperties();

  @Mock
  SpringAddonsOidcClientProperties addonsClientProperties;

  @Mock
  SpringAddonsOidcProperties addonsProperties;

  @Mock
  HttpServletRequest request;

  @Mock
  HttpServletResponse response;

  @Mock
  OAuth2AuthenticationToken authentication;

  @Mock
  OidcUser oidcUser;

  @BeforeEach
  void setUp() {
    when(addonsProperties.getClient()).thenReturn(addonsClientProperties);
  }

  @Test
  void givenNeitherClientUriNorDefaultPostLogoutAllowedUriPatternsNorPostLogoutRedirectUriHaHaveAnAuthority_whenBuildSpringAddonsLogoutSuccessHandler_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLogoutRedirectUri()).thenReturn(URI.create("/ui/"));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);

    assertDoesNotThrow(() -> new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties));
  }

  @Test
  void givenClientUriHasAnAuthorityButPostLogoutRedirectUridoesNot_whenBuildSpringAddonsLogoutSuccessHandler_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLogoutRedirectUri()).thenReturn(URI.create("/ui/"));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);

    assertDoesNotThrow(() -> new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties));
  }

  @Test
  void givenNeitherClientUriNorDefaultPostLogoutAllowedUriPatternsHaveAnAuthorityButConfiguredPostLogoutRedirectUriHasOne_whenBuildSpringAddonsLogoutSuccessHandler_thenThrows() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("https://localhost:8080/ui/"));

    assertThrows(MisconfiguredPostLogoutUriException.class,
        () -> new SpringAddonsLogoutSuccessHandler(uriBuilder, clientRegistrationRepository,
            addonsProperties));
  }

  @Test
  void givenClientUriAndConfiguredPostLogoutRedirectUriHaveSameAuthority_whenBuildSpringAddonsLogoutSuccessHandler_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("https://localhost:8080/ui/"));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);

    assertDoesNotThrow(() -> new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties));
  }

  @Test
  void givenClientUriAndConfiguredPostLogoutRedirectUriHaveDifferentAuthorities_whenBuildSpringAddonsLogoutSuccessHandler_thenThrows() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns()).thenReturn(
        List.of(Pattern.compile("https://localhost:8080(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("http://localhost:4200"));

    assertThrows(MisconfiguredPostLogoutUriException.class,
        () -> new SpringAddonsLogoutSuccessHandler(uriBuilder, clientRegistrationRepository,
            addonsProperties));
  }

  @Test
  void givenPostLogoutAllowedUriPatternAllowsAnySubDomainAndConfiguredPostLogoutRedirectUriHasHostInDomain_whenBuildSpringAddonsLogoutSuccessHandler_thenDoesNotThrow() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns()).thenReturn(List
        .of(Pattern.compile(".*\\.chose\\.pf(/.*)?"), Pattern.compile(".*\\.machin\\.pf(/.*)?")));
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("https://machin.chose.pf"));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);

    assertDoesNotThrow(() -> new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties));
  }

  @Test
  void givenPostLogoutAllowedUriPatternAllowsAnySubDomainAndConfiguredPostLogoutRedirectUriHasHostInAnotherDomain_whenBuildSpringAddonsLogoutSuccessHandler_thenThrows() {
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns()).thenReturn(List
        .of(Pattern.compile(".*\\.chose\\.pf(/.*)?"), Pattern.compile(".*\\.machin\\.pf(/.*)?")));
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("https://machinchose.pf/"));

    assertThrows(MisconfiguredPostLogoutUriException.class,
        () -> new SpringAddonsLogoutSuccessHandler(uriBuilder, clientRegistrationRepository,
            addonsProperties));
  }

  @Test
  void givenDefaultPostLogoutAllowedUriPatternsForClientUriWithAnAuthority_whenOnLogoutSuccessWithPostLogoutRedirectUriHeaderHavingNoAuthority_thenRedirected()
      throws IOException, ServletException {
    final var postLogoutUri = URI.create("/ui/login");
    final var logoutUri =
        "https://provider/logout?id_token_hint=machin.truc.chose&client_id=bff&post_logout_redirect_uri="
            + postLogoutUri.toString();
    when(oidcUser.getIdToken()).thenReturn(new OidcIdToken("machin.truc.chose", Instant.now(),
        Instant.now().plusMillis(1), Map.of("bidule", "chouette")));
    when(authentication.getPrincipal()).thenReturn(oidcUser);
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("https://localhost(/.*)?"), Pattern.compile("/.*")));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);
    when(addonsClientProperties.getPostLogoutRedirectUri())
        .thenReturn(URI.create("https://localhost/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
        .thenReturn(postLogoutUri.toString());
    when(request.getIntHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER))
        .thenReturn(-1);
    when(uriBuilder.getLogoutRequestUri(any(), any(), any())).thenReturn(Optional.of(logoutUri));

    final var resolver = new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties);
    resolver.onLogoutSuccess(request, response, authentication);

    verify(response).setStatus(HttpStatus.FOUND.value());
    verify(response).setHeader(HttpHeaders.LOCATION, logoutUri);
  }

  @Test
  void givenDefaultPostLogoutAllowedUriPatternsForClientUriWithoutAnAuthority_whenOnLogoutSuccesswhenOnLogoutSuccessWithPostLogoutRedirectUriHeaderHavingNoAuthority_thenRedirected()
      throws IOException, ServletException {
    final var postLogoutUri = URI.create("/ui/login");
    final var logoutUri =
        "https://provider/logout?id_token_hint=machin.truc.chose&client_id=bff&post_logout_redirect_uri="
            + postLogoutUri.toString();
    when(oidcUser.getIdToken()).thenReturn(new OidcIdToken("machin.truc.chose", Instant.now(),
        Instant.now().plusMillis(1), Map.of("bidule", "chouette")));
    when(authentication.getPrincipal()).thenReturn(oidcUser);
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);
    when(addonsClientProperties.getPostLogoutRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
        .thenReturn(postLogoutUri.toString());
    when(request.getIntHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER))
        .thenReturn(-1);
    when(uriBuilder.getLogoutRequestUri(any(), any(), any())).thenReturn(Optional.of(logoutUri));

    final var resolver = new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties);
    resolver.onLogoutSuccess(request, response, authentication);

    verify(response).setStatus(HttpStatus.FOUND.value());
    verify(response).setHeader(HttpHeaders.LOCATION, logoutUri);
  }

  @Test
  void givenDefaultPostLogoutAllowedUriPatternsForClientUriWithoutAnAuthority_whenOnLogoutSuccesswhenOnLogoutSuccessWithPostLogoutRedirectUriHeaderHavingAnAuthority_thenThrow()
      throws IOException, ServletException {
    final var postLogoutUri = URI.create("https://localhost/ui/login");
    when(authentication.getPrincipal()).thenReturn(oidcUser);
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getOauth2Redirections()).thenReturn(oauth2Redirections);
    when(addonsClientProperties.getPostLogoutRedirectUri()).thenReturn(URI.create("/ui/"));
    when(request.getHeader(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
        .thenReturn(postLogoutUri.toString());

    final var resolver = new SpringAddonsLogoutSuccessHandler(uriBuilder,
        clientRegistrationRepository, addonsProperties);
    assertThrows(InvalidRedirectionUriException.class,
        () -> resolver.onLogoutSuccess(request, response, authentication));

    verify(response, never()).setStatus(HttpStatus.FOUND.value());
    verify(response, never()).setHeader(eq(HttpHeaders.LOCATION), any());
  }
}
