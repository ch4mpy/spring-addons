package com.c4_soft.springaddons.samples.resourceserver.greetings;

import java.util.Objects;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Method security is not limited to controllers. This {@code @Service} is unit-tested with the
 * security context populated by test annotations, without {@code WebTestClient}: see
 * {@code GreetingsServiceTest}.
 */
@Service
public class GreetingsService {

  @PreAuthorize("isAuthenticated()")
  public Mono<GreetingResponse> greet(JwtAuthenticationToken auth) {
    final var message = "Hi %s! You are granted with %s.".formatted(
        Objects.requireNonNullElse(auth.getToken().getClaimAsString(StandardClaimNames.GIVEN_NAME),
            auth.getName()),
        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
    return Mono.just(response(message, auth));
  }

  @PreAuthorize("hasAuthority('NICE')")
  public Mono<GreetingResponse> nice(JwtAuthenticationToken auth) {
    return Mono.just(response("Dear %s, glad to see you!".formatted(auth.getName()), auth));
  }

  private static GreetingResponse response(String message, JwtAuthenticationToken auth) {
    return new GreetingResponse(message, auth.getName(), auth.getToken().getClaimAsString("iss"),
        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
  }
}
