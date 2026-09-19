package com.c4_soft.springaddons.samples.bff;

import java.util.List;
import java.util.stream.StreamSupport;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lists the URIs a frontend can navigate to for login: one per {@code authorization_code} registration
 * in {@code spring.security.oauth2.client.registration}. Spring Security's
 * {@code OAuth2AuthorizationRequestRedirectFilter} intercepts {@code /oauth2/authorization/{registrationId}}
 * and starts the flow.
 */
@RestController
public class LoginOptionsController {
  private final List<LoginOption> loginOptions;

  public LoginOptionsController(InMemoryClientRegistrationRepository clientRegistrationRepository) {
    this.loginOptions = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
        .filter(reg -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType()))
        .map(LoginOption::of).toList();
  }

  @GetMapping("/login-options")
  public List<LoginOption> getLoginOptions() {
    return loginOptions;
  }

  public record LoginOption(String label, String loginUri) {
    static LoginOption of(ClientRegistration registration) {
      return new LoginOption(registration.getClientName(),
          "/oauth2/authorization/" + registration.getRegistrationId());
    }
  }
}
