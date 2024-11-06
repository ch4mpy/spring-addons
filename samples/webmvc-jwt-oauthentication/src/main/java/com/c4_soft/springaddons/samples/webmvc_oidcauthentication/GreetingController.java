package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class GreetingController {
  private final MessageService messageService;

  @GetMapping("/greet")
  public String greet(OAuthentication<OpenidToken> auth) {
    return messageService.greet(auth);
  }

  @GetMapping("/secured-route")
  public String securedRoute() {
    return messageService.getSecret();
  }

  @GetMapping("/secured-method")
  @PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
  public String securedMethod() {
    return messageService.getSecret();
  }

  @GetMapping("/claims")
  public Map<String, Object> getClaims(@AuthenticationPrincipal OpenidClaimSet token) {
    return token;
  }
}
