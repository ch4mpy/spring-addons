package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.WebFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.OAuth2RedirectionProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class SpringAddonsServerLogoutSuccessHandlerTest {

  @Mock
  LogoutRequestUriBuilder uriBuilder;

  @Mock
  ReactiveClientRegistrationRepository clientRegistrationRepository;

  @Mock
  SpringAddonsOidcClientProperties addonsClientProperties;

  @Mock
  SpringAddonsOidcProperties addonsProperties;

  @Mock
  OAuth2AuthenticationToken authentication;

  @Mock
  OidcUser oidcUser;

  @BeforeEach
  void setUp() {
    when(addonsProperties.getClient()).thenReturn(addonsClientProperties);
    when(addonsClientProperties.getPostLogoutAllowedUriPatterns())
        .thenReturn(List.of(Pattern.compile("/.*")));
    when(addonsClientProperties.getOauth2Redirections())
        .thenReturn(new OAuth2RedirectionProperties());
    when(addonsClientProperties.getPostLogoutRedirectUri()).thenReturn(URI.create("/ui/"));
  }

  @Test
  void givenOidcUser_whenOnLogoutSuccess_thenRedirectedToRpInitiatedLogoutUri() {
    final var logoutUri = "https://op/logout?id_token_hint=a.b.c&post_logout_redirect_uri=/ui/bye";
    when(oidcUser.getIdToken()).thenReturn(new OidcIdToken("a.b.c", Instant.now(),
        Instant.now().plusSeconds(60), Map.of("sub", "ch4mp")));
    when(authentication.getPrincipal()).thenReturn(oidcUser);
    when(authentication.getAuthorizedClientRegistrationId()).thenReturn("reg");
    when(clientRegistrationRepository.findByRegistrationId("reg"))
        .thenReturn(Mono.just(registration()));
    when(uriBuilder.getLogoutRequestUri(any(), any(), any())).thenReturn(Optional.of(logoutUri));
    final var exchange = exchange("/ui/bye");

    handler().onLogoutSuccess(exchange, authentication).block();

    assertThat(exchange.getExchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getExchange().getResponse().getHeaders().getLocation())
        .isEqualTo(URI.create(logoutUri));
  }

  @Test
  void givenOAuth2LoginWithoutOpenid_whenOnLogoutSuccess_thenRedirectedToPostLogoutUri() {
    when(authentication.getPrincipal()).thenReturn(mock(OAuth2User.class));
    final var exchange = exchange("/ui/bye");

    handler().onLogoutSuccess(exchange, authentication).block();

    verify(uriBuilder, never()).getLogoutRequestUri(any(), any(), any());
    assertThat(exchange.getExchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getExchange().getResponse().getHeaders().getLocation())
        .isEqualTo(URI.create("/ui/bye"));
  }

  @Test
  void givenNoAuthentication_whenOnLogoutSuccess_thenRedirectedToDefaultPostLogoutUri() {
    final var exchange = exchange(null);

    handler().onLogoutSuccess(exchange, null).block();

    assertThat(exchange.getExchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getExchange().getResponse().getHeaders().getLocation())
        .isEqualTo(URI.create("/ui/"));
  }

  @Test
  void givenSchemeRelativePostLogoutUri_whenOnLogoutSuccess_thenErrors() {
    final var exchange = exchange("//evil.com/bye");

    assertThatThrownBy(() -> handler().onLogoutSuccess(exchange, authentication).block())
        .isInstanceOf(InvalidRedirectionUriException.class);

    assertThat(exchange.getExchange().getResponse().getHeaders().getLocation()).isNull();
  }

  private SpringAddonsServerLogoutSuccessHandler handler() {
    return new SpringAddonsServerLogoutSuccessHandler(uriBuilder, clientRegistrationRepository,
        addonsProperties);
  }

  private static WebFilterExchange exchange(String postLogoutUriHeader) {
    final var request = MockServerHttpRequest.get("http://localhost/logout");
    if (postLogoutUriHeader != null) {
      request.header(SpringAddonsOidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER,
          postLogoutUriHeader);
    }
    return new WebFilterExchange(MockServerWebExchange.from(request), mock(WebFilterChain.class));
  }

  private static ClientRegistration registration() {
    return ClientRegistration.withRegistrationId("reg").clientId("client-id")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://op/authorize").tokenUri("https://op/token").build();
  }
}
