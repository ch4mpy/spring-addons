package com.c4_soft.springaddons.samples.clientandresourceserver.ui;

import org.jspecify.annotations.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import lombok.RequiredArgsConstructor;

/**
 * Server-side rendered pages, secured with a session by the client filter chain. Unauthorized
 * requests to {@code /ui/**} are redirected to login, which is what a browser expects, while
 * unauthorized requests to the REST API get a 401.
 */
@Controller
@RequiredArgsConstructor
public class UiController {
  private final GreetingsApi greetingsApi;

  @GetMapping("/")
  public String getIndex(Model model, @Nullable Authentication auth) {
    model.addAttribute("username", auth == null || !auth.isAuthenticated() ? null : auth.getName());
    return "index";
  }

  @GetMapping("/ui/greeting")
  @PreAuthorize("isAuthenticated()")
  public String getGreeting(Model model) {
    // calls the REST API of this very application: the request leaves with the access token in
    // session as a Bearer, and comes back through the resource server filter chain
    model.addAttribute("greeting", greetingsApi.getMyGreeting());
    return "greeting";
  }
}
