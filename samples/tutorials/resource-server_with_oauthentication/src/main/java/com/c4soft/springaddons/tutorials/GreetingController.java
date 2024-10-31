package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

  @GetMapping("/greet")
  public MessageDto getGreeting(OAuthentication<OpenidToken> auth) {
    return new MessageDto("Hi %s! You are granted with: %s and your email is %s."
        .formatted(auth.getName(), auth.getAuthorities(), auth.getClaims().getEmail()));
  }

  @GetMapping("/nice")
  @PreAuthorize("hasAuthority('NICE')")
  public MessageDto getNiceGreeting(OAuthentication<OpenidToken> auth) {
    return new MessageDto(
        "Dear %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities()));
  }

  static record MessageDto(String body) {
  }
}
