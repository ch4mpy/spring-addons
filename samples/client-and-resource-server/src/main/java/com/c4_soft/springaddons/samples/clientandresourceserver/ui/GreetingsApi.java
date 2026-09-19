package com.c4_soft.springaddons.samples.clientandresourceserver.ui;

import com.c4_soft.springaddons.samples.clientandresourceserver.api.GreetingsController.GreetingResponse;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/** The REST API of this application, as its own UI consumes it. */
@HttpExchange
public interface GreetingsApi {

  @GetExchange("/greetings/me")
  GreetingResponse getMyGreeting();
}
