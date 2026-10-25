package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import reactor.core.publisher.Mono;

class ClientAuthorizationExceptionWebFilterTest {
  private final List<OAuth2ClientRefusal> refusals = new ArrayList<>();
  /**
   * "reg" is the registration users log in with, "github" another authorization_code one (needing
   * its own consent), "cc" a client_credentials one
   */
  private static final InMemoryReactiveClientRegistrationRepository REGISTRATIONS =
      new InMemoryReactiveClientRegistrationRepository(
          ClientRegistration.withRegistrationId("reg").clientId("client-id")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://op/authorize").tokenUri("https://op/token").build(),
          ClientRegistration.withRegistrationId("github").clientId("client-id")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://github/authorize").tokenUri("https://github/token")
              .build(),
          ClientRegistration.withRegistrationId("cc").clientId("machine")
              .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
              .tokenUri("https://op/token").build());

  private final ClientAuthorizationExceptionWebFilter filter =
      new ClientAuthorizationExceptionWebFilter(REGISTRATIONS, (exchange, refusal) -> {
        refusals.add(refusal);
        exchange.getResponse().setStatusCode(refusal.status());
        return exchange.getResponse().setComplete();
      });
  private final WebSessionServerSecurityContextRepository securityContextRepository =
      new WebSessionServerSecurityContextRepository();
  private final TestingAuthenticationToken authentication =
      new TestingAuthenticationToken("ch4mp", "", "ROLE_USER");

  /**
   * An exchange with a started session holding a security context, as after {@code oauth2Login}
   */
  private MockServerWebExchange loggedInExchange() {
    final var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/bff/api/greetings/me"));
    securityContextRepository.save(exchange, new SecurityContextImpl(authentication)).block();
    return exchange;
  }

  private static WebFilterChain erroring(Throwable error) {
    return exchange -> Mono.error(error);
  }

  private static WebSession session(MockServerWebExchange exchange) {
    return exchange.getSession().block();
  }

  @Test
  void givenChainErrorsWithClientAuthorizationRequiredException_whenFilter_thenLoggedOutAndUnauthorized() {
    final var exchange = loggedInExchange();
    assertThat(session(exchange).isStarted()).isTrue();

    filter.filter(exchange, erroring(new ClientAuthorizationRequiredException("reg")))
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
    assertThat(session(exchange).isExpired()).isTrue();
    assertThat(securityContextRepository.load(exchange).blockOptional()).isEmpty();
    assertThat(refusals).singleElement().satisfies(refusal -> {
      assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.AUTHORIZATION_REQUIRED);
      assertThat(refusal.cause()).isInstanceOf(ClientAuthorizationRequiredException.class);
    });
  }

  @Test
  void givenChainErrorsWithClientAuthorizationExceptionForRefusedRefresh_whenFilter_thenLoggedOutAndUnauthorized() {
    final var exchange = loggedInExchange();

    filter.filter(exchange, erroring(
        new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")))
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(session(exchange).isExpired()).isTrue();
    assertThat(securityContextRepository.load(exchange).blockOptional()).isEmpty();
    assertThat(refusals).singleElement().satisfies(refusal -> assertThat(
        ((ClientAuthorizationException) refusal.cause()).getError().getErrorCode())
            .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
  }

  @Test
  void givenNoSecurityContextInReactorContext_whenFilter_thenStillLoggedOutAndUnauthorized() {
    final var exchange = loggedInExchange();

    filter.filter(exchange, erroring(new ClientAuthorizationRequiredException("reg"))).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(session(exchange).isExpired()).isTrue();
  }

  @Test
  void givenErrorCausedByClientAuthorizationException_whenFilter_thenLoggedOutAndUnauthorized() {
    final var exchange = loggedInExchange();
    // what retryWhen(...) signals once retries are exhausted, for instance
    final var wrapped = new IllegalStateException("Retries exhausted",
        new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg"));

    filter.filter(exchange, erroring(wrapped)).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(session(exchange).isExpired()).isTrue();
  }

  @Test
  void givenOAuth2LoginWithTheFailingRegistration_whenFilter_thenLoggedOutAndUnauthorized() {
    final var exchange = loggedInExchange();

    filter.filter(exchange, erroring(new ClientAuthorizationRequiredException("reg")))
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(oauth2Login("reg")))
        .block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(session(exchange).isExpired()).isTrue();
  }

  @Test
  void givenOAuth2LoginWithAnotherRegistration_whenFilter_thenPropagatedAndSessionKept() {
    final var exchange = loggedInExchange();
    // left to Spring Security's incremental authorization (the redirect web filter upstream)
    final var error = new ClientAuthorizationRequiredException("github");

    assertThatThrownBy(() -> filter.filter(exchange, erroring(error))
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(oauth2Login("reg")))
        .block()).isSameAs(error);

    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenUnknownRegistration_whenFilter_thenPropagatedAndSessionKept() {
    final var exchange = loggedInExchange();
    final var error = new ClientAuthorizationRequiredException("unknown");

    assertThatThrownBy(() -> filter.filter(exchange, erroring(error)).block()).isSameAs(error);

    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(refusals).isEmpty();
  }

  private static OAuth2AuthenticationToken oauth2Login(String registrationId) {
    final var authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
    return new OAuth2AuthenticationToken(
        new DefaultOAuth2User(authorities, Map.of("sub", "ch4mp"), "sub"), authorities,
        registrationId);
  }

  @Test
  void givenClientCredentialsRegistration_whenFilter_thenPropagatedAndSessionKept() {
    final var exchange = loggedInExchange();
    final var error =
        new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), "cc");

    assertThatThrownBy(() -> filter.filter(exchange, erroring(error)).block()).isSameAs(error);

    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(securityContextRepository.load(exchange).blockOptional()).isPresent();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenResponseAlreadyCommitted_whenFilter_thenPropagatedAndSessionKept() {
    final var exchange = loggedInExchange();
    exchange.getResponse().setComplete().block();
    final var error = new ClientAuthorizationRequiredException("reg");

    assertThatThrownBy(() -> filter.filter(exchange, erroring(error)).block()).isSameAs(error);

    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainErrorsWithAnotherException_whenFilter_thenPropagatedAndSessionKept() {
    final var exchange = loggedInExchange();
    final var error = new IllegalStateException("something else");

    assertThatThrownBy(() -> filter.filter(exchange, erroring(error)).block()).isSameAs(error);

    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(securityContextRepository.load(exchange).blockOptional()).isPresent();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainCompletes_whenFilter_thenResponseAndSessionUntouched() {
    final var exchange = loggedInExchange();

    filter.filter(exchange, ex -> Mono.empty()).block();

    assertThat(exchange.getResponse().getStatusCode()).isNull();
    assertThat(session(exchange).isExpired()).isFalse();
    assertThat(refusals).isEmpty();
  }
}
