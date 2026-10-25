package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Writes the response to a request the auto-configured client filter-chain refuses with a status:
 * {@code 401} when the client must be authorized again (see
 * {@link ClientAuthorizationExceptionWebFilter}), {@code 400} when a post-login URI is not allowed
 * (see {@link InvalidPostLoginUriWebFilter}).
 * </p>
 * <p>
 * The default, {@link SpringAddonsServerOAuth2ClientRefusalWriter}, writes the status alone. Expose
 * a bean of this type to write a body (an RFC 9457 problem for instance) or another status.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@FunctionalInterface
public interface ServerOAuth2ClientRefusalWriter {

  Mono<Void> write(ServerWebExchange exchange, OAuth2ClientRefusal refusal);
}
