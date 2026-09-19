package com.c4_soft.springaddons.security.oidc.starter.reactive;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ServerHttpRequestSupport.MissingHeaderException;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ServerHttpRequestSupport.MultiValuedHeaderException;
import reactor.core.publisher.Mono;

class ServerHttpRequestSupportTest {

  @Test
  void givenHeaderHasOneValue_whenGetUniqueHeader_thenValue() {
    assertThat(inExchange(ServerHttpRequestSupport.getUniqueHeader("X-Test"), "a").block())
        .isEqualTo("a");
  }

  @Test
  void givenHeaderIsMissing_whenGetUniqueHeader_thenMissingHeaderError() {
    final var mono = inExchange(ServerHttpRequestSupport.getUniqueHeader("X-Test"));

    assertThatThrownBy(mono::block).isInstanceOf(MissingHeaderException.class);
  }

  @Test
  void givenHeaderHasSeveralValues_whenGetUniqueHeader_thenMultiValuedHeaderError() {
    final var mono = inExchange(ServerHttpRequestSupport.getUniqueHeader("X-Test"), "a", "b");

    assertThatThrownBy(mono::block).isInstanceOf(MultiValuedHeaderException.class);
  }

  private static <T> Mono<T> inExchange(Mono<T> mono, String... headerValues) {
    final var request = MockServerHttpRequest.get("/");
    for (final var value : headerValues) {
      request.header("X-Test", value);
    }
    return mono.contextWrite(
        ctx -> ctx.put(ServerWebExchange.class, MockServerWebExchange.from(request)));
  }
}
