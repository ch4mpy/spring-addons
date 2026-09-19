package com.c4_soft.springaddons.samples.resourceserver.greetings;

import java.util.Objects;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

/**
 * Method security is not limited to controllers. This {@code @Service} is unit-tested with the
 * security context populated by test annotations, without {@code MockMvc}: see
 * {@code GreetingsServiceTest}.
 */
@Service
public class GreetingsService {

  @PreAuthorize("isAuthenticated()")
  public GreetingResponse greet(OAuthentication<OpenidToken> auth) {
    // OpenidToken exposes typed accessors to standard OpenID claims
    final var claims = auth.getAttributes();
    final var message = "Hi %s! You are granted with %s.".formatted(
        Objects.requireNonNullElse(claims.getGivenName(), auth.getName()),
        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
    return response(message, auth);
  }

  @PreAuthorize("hasAuthority('NICE')")
  public GreetingResponse nice(OAuthentication<OpenidToken> auth) {
    return response("Dear %s, glad to see you!".formatted(auth.getName()), auth);
  }

  private static GreetingResponse response(String message, OAuthentication<OpenidToken> auth) {
    return new GreetingResponse(message, auth.getName(),
        auth.getAttributes().getIssuer() == null ? null
            : auth.getAttributes().getIssuer().toString(),
        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
  }
}
