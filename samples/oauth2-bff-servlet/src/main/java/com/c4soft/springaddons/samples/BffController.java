package com.c4soft.springaddons.samples;

import java.net.URISyntaxException;
import java.util.List;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.validation.constraints.NotEmpty;

@RestController
public class BffController {
  private final List<LoginOptionDto> loginOptions;

  public BffController(OAuth2ClientProperties clientProps,
      SpringAddonsOidcProperties addonsProperties) {
    this.loginOptions =
        clientProps.getRegistration().entrySet().stream()
            .filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
            .map(
                e -> new LoginOptionDto(e.getValue().getProvider(),
                    "%s/oauth2/authorization/%s"
                        .formatted(addonsProperties.getClient().getClientUri(), e.getKey())))
            .toList();
  }

  @GetMapping(path = "/login-options", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<LoginOptionDto> getLoginOptions(Authentication auth) throws URISyntaxException {
    final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
    return isAuthenticated ? List.of() : this.loginOptions;
  }

  public static record LoginOptionDto(@NotEmpty String label, @NotEmpty String loginUri) {
  }
}
