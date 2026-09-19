package com.c4_soft.springaddons.samples.restclient;

import java.util.List;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/** A slice of the Keycloak admin API, as a client sees it. */
@HttpExchange
public interface KeycloakUsersApi {

  @GetExchange("/{realm}/users")
  List<KeycloakUser> findUsers(@PathVariable String realm, @RequestParam("search") String search,
      @RequestParam("max") int max);

  record KeycloakUser(String id, String username, String firstName, String lastName, String email) {
  }
}
