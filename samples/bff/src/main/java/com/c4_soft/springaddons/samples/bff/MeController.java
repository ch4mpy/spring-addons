package com.c4_soft.springaddons.samples.bff;

import java.util.List;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * What a frontend needs to know about the current user. {@code /me} is in {@code permit-all}: an
 * anonymous request is answered with an empty user, not with a 401.
 */
@RestController
public class MeController {

  @GetMapping("/me")
  public UserInfo getMe(@Nullable Authentication auth) {
    if (auth instanceof OAuth2AuthenticationToken oauth
        && oauth.getPrincipal() instanceof OidcUser oidcUser) {
      // the authorities were mapped from the ID token claims by the auto-configured
      // GrantedAuthoritiesMapper, using the com.c4-soft.springaddons.oidc.ops[].authorities rules
      return new UserInfo(oidcUser.getPreferredUsername(), oidcUser.getEmail(),
          oauth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
    }
    return UserInfo.ANONYMOUS;
  }

  public record UserInfo(@Nullable String username, @Nullable String email, List<String> roles) {
    static final UserInfo ANONYMOUS = new UserInfo(null, null, List.of());
  }
}
