package com.c4_soft.springaddons.samples.resourceserver.greetings;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import lombok.RequiredArgsConstructor;

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
  public GreetingResponse getPublicGreeting() {
    return new GreetingResponse("Hello, whoever you are.", null, null, null);
  }

  /**
   * @param auth the {@code Authentication} built by the converter bean in {@code SecurityConfig}.
   *        The parameter type is what Spring resolves from the security context: with Spring's
   *        default converter, this would be a {@code JwtAuthenticationToken}.
   */
  @GetMapping("/me")
  @PreAuthorize("isAuthenticated()")
  public GreetingResponse getMyGreeting(OAuthentication<OpenidToken> auth) {
    return greetingsService.greet(auth);
  }

  /**
   * Access control on the {@code @Service} rather than on the controller: see
   * {@link GreetingsService#nice(OAuthentication)}.
   */
  @GetMapping("/nice")
  public GreetingResponse getNiceGreeting(OAuthentication<OpenidToken> auth) {
    return greetingsService.nice(auth);
  }
}
