package com.c4soft.springaddons.samples;

import java.net.URISyntaxException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.view.RedirectView;
import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
public class UiController {

  @GetMapping({"", "/",})
  public RedirectView getIndex() throws URISyntaxException {
    return new RedirectView("/ui/");
  }

  @GetMapping({"/ui", "/ui/"})
  public String getIndex(Model model, Authentication auth) {
    model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
    model.addAttribute("username", auth == null ? null : auth.getName());
    return "index";
  }

  @PutMapping("/ui/xhr")
  @ResponseBody
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void post() {}
}
