package com.c4soft.springaddons.samples;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Controller
@Slf4j
public class UiController {

  @GetMapping({"", "/",})
  public Mono<Void> getIndex(ServerHttpResponse response) throws URISyntaxException {
    response.setStatusCode(HttpStatus.PERMANENT_REDIRECT);
    response.getHeaders().setLocation(URI.create("/ui"));
    return response.setComplete();
  }

  @GetMapping({"/ui", "/ui/"})
  public String getIndex(Model model, Authentication auth) {
    model.addAttribute("isAuthenticated",
        auth != null && !Objects.equals(auth.getName(), "anonymousUser"));
    model.addAttribute("username", auth == null ? null : auth.getName());
    return "index";
  }

  @PutMapping("/ui/xhr")
  @ResponseBody
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void post() {}
}
