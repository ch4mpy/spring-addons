package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.c4soft.springaddons.tutorials.SecurityConfig.MyAuth;

@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

  @GetMapping("/greet")
  public MessageDto getGreeting(MyAuth auth) {
    // email From ID token in X-ID-Token header
    // Authorities from access token in Authorization header
    return new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getIdToken().getEmail(),
        auth.getAuthorities()));
  }

  static record MessageDto(String body) {
  }
}
