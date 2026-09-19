package com.c4_soft.springaddons.samples.clientandresourceserver.api;

import java.util.List;
import org.jspecify.annotations.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The REST API, secured with access tokens by the resource server filter chain. {@code /api/**} is
 * not in the client chain security matchers, so these routes never see a session: an unauthorized
 * request gets a 401, not a redirection to login.
 */
@RestController
@RequestMapping("/api/greetings")
public class GreetingsController {

  @GetMapping("/public")
  public GreetingResponse getPublicGreeting() {
    return new GreetingResponse("Hello, whoever you are.", null, null);
  }

  @GetMapping("/me")
  @PreAuthorize("isAuthenticated()")
  public GreetingResponse getMyGreeting(JwtAuthenticationToken auth) {
    return new GreetingResponse("Hi %s, this comes from the REST API.".formatted(auth.getName()),
        auth.getName(),
        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
  }

  public record GreetingResponse(String message, @Nullable String username,
      @Nullable List<String> authorities) {
  }
}
