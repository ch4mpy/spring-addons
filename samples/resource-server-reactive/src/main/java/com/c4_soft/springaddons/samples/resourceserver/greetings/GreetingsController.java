package com.c4_soft.springaddons.samples.resourceserver.greetings;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/greetings")
@RequiredArgsConstructor
public class GreetingsController {
  private final GreetingsService greetingsService;

  /**
   * Anonymous access is granted by the {@code permit-all} property (not by an annotation: the
   * default access rule of the auto-configured filter chain is {@code authenticated()}).
   */
  @GetMapping("/public")
  public Mono<GreetingResponse> getPublicGreeting() {
    return Mono.just(new GreetingResponse("Hello, whoever you are.", null, null, null));
  }

  /**
   * @param auth the default {@code Authentication} for a resource server with a JWT decoder. Its
   *        name and authorities are still resolved from the claims configured in
   *        {@code com.c4-soft.springaddons.oidc.ops} for the token issuer.
   */
  @GetMapping("/me")
  @PreAuthorize("isAuthenticated()")
  public Mono<GreetingResponse> getMyGreeting(JwtAuthenticationToken auth) {
    return greetingsService.greet(auth);
  }

  /**
   * Access control on the {@code @Service} rather than on the controller: see
   * {@link GreetingsService#nice(JwtAuthenticationToken)}.
   */
  @GetMapping("/nice")
  public Mono<GreetingResponse> getNiceGreeting(JwtAuthenticationToken auth) {
    return greetingsService.nice(auth);
  }
}
