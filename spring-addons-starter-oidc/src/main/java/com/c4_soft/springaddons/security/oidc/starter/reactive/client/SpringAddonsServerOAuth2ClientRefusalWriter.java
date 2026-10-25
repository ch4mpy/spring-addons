package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Default {@link ServerOAuth2ClientRefusalWriter}: the status of the refusal, no body, no
 * {@code Location}.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class SpringAddonsServerOAuth2ClientRefusalWriter implements ServerOAuth2ClientRefusalWriter {

  @Override
  public Mono<Void> write(ServerWebExchange exchange, OAuth2ClientRefusal refusal) {
    return Mono.defer(() -> {
      log.debug("{} on {}: answering {} ({})", refusal.kind(), exchange.getRequest().getPath(),
          refusal.status().value(), refusal.cause().getMessage());
      exchange.getResponse().setStatusCode(refusal.status());
      return exchange.getResponse().setComplete();
    });
  }
}
