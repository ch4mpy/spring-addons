package com.c4soft.springaddons.tutorials.ui;

import java.net.URISyntaxException;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.view.RedirectView;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
public class UiController {
  private final GreetApi greetApi;
  private final List<String> activeProfiles;

  public UiController(GreetApi greetApi,
      @Value("${spring.profiles.active:[]}") List<String> activeProfiles) {
    super();
    this.greetApi = greetApi;
    this.activeProfiles = activeProfiles;
  }

  @GetMapping({"", "/",})
  public RedirectView getIndex() throws URISyntaxException {
    return new RedirectView("/ui/");
  }

  @GetMapping({"/ui", "/ui/"})
  public String getIndex(Model model, Authentication auth) {
    model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
    return "index";
  }

  @GetMapping("/ui/greet")
  @PreAuthorize("isAuthenticated()")
  public String getGreeting(HttpServletRequest request, Authentication auth, Model model)
      throws URISyntaxException {
    try {
      final var greeting = greetApi.getGreeting();
      model.addAttribute("greeting", greeting);
    } catch (Throwable e) {
      model.addAttribute("greeting", e.getMessage());
    }
    return activeProfiles.contains("javascript") ? "greet-js" : "greet";
  }

  @PutMapping("/ui/put")
  @ResponseBody
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void post() {}
}
