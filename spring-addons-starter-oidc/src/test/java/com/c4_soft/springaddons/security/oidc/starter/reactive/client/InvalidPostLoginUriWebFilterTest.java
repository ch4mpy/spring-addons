package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import reactor.core.publisher.Mono;

class InvalidPostLoginUriWebFilterTest {
  private final List<OAuth2ClientRefusal> refusals = new ArrayList<>();
  private final InvalidPostLoginUriWebFilter filter =
      new InvalidPostLoginUriWebFilter((exchange, refusal) -> {
        refusals.add(refusal);
        exchange.getResponse().setStatusCode(refusal.status());
        return exchange.getResponse().setComplete();
      });

  @Test
  void givenChainErrorsWithInvalidPostLoginUriException_whenFilter_thenBadRequestWithoutLocation() {
    final var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/oauth2/authorization/reg"));

    filter.filter(exchange, ex -> Mono.error(new InvalidPostLoginUriException("https://evil.com")))
        .block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
    assertThat(exchange.getSession().block().isStarted()).isFalse();
    assertThat(refusals).singleElement().satisfies(refusal -> {
      assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.INVALID_POST_LOGIN_URI);
      assertThat(refusal.cause()).hasMessageContaining("https://evil.com");
    });
  }

  @Test
  void givenChainErrorsWithPostLogoutUriRefusal_whenFilter_thenPropagated() {
    final var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/logout"));
    // what SpringAddonsServerLogoutSuccessHandler signals for a post-logout URI which is not allowed
    final var error = new InvalidRedirectionUriException("https://evil.com");

    assertThatThrownBy(() -> filter.filter(exchange, ex -> Mono.error(error)).block())
        .isSameAs(error);

    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainErrorsWithAnotherException_whenFilter_thenPropagated() {
    final var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/oauth2/authorization/reg"));
    final var error = new IllegalStateException("something else");

    assertThatThrownBy(() -> filter.filter(exchange, ex -> Mono.error(error)).block())
        .isSameAs(error);

    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainCompletes_whenFilter_thenResponseUntouched() {
    final var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/oauth2/authorization/reg"));

    filter.filter(exchange, ex -> Mono.empty()).block();

    assertThat(exchange.getResponse().getStatusCode()).isNull();
    assertThat(refusals).isEmpty();
  }
}
