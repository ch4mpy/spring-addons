package com.c4_soft.springaddons.samples.restclient;

import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.samples.restclient.KeycloakUsersApi.KeycloakUser;

/**
 * Two ways of consuming an API with clients auto-configured by spring-addons-starter-rest: an
 * injected {@code RestClient} bean, and an {@code @HttpExchange} proxy backed by another one.
 */
@RestController
public class ProxyController {
  private final RestClient greetingsClient;
  private final KeycloakUsersApi keycloakUsersApi;

  /**
   * @param greetingsClient the bean auto-configured from
   *        {@code com.c4-soft.springaddons.rest.client.greetings-client} (the bean name is the
   *        camelCase of the property key). Its requests carry the access token of the request being
   *        processed, because of {@code authorization.oauth2.forward-bearer}.
   * @param keycloakUsersApi a proxy from the {@code keycloak-admin-group}, whose requests are
   *        authorized with a token obtained with the {@code keycloak-admin} registration
   *        ({@code client_credentials}), not with the token of the current user.
   */
  public ProxyController(RestClient greetingsClient, KeycloakUsersApi keycloakUsersApi) {
    this.greetingsClient = greetingsClient;
    this.keycloakUsersApi = keycloakUsersApi;
  }

  /** Calls the resource-server sample on behalf of the current user. */
  @GetMapping("/relayed-greeting")
  @PreAuthorize("isAuthenticated()")
  public Map<String, Object> getRelayedGreeting() {
    return greetingsClient.get().uri("/greetings/me").retrieve()
        .body(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});
  }

  /** Calls the Keycloak admin API as this application, not as the current user. */
  @GetMapping("/users")
  @PreAuthorize("hasAuthority('NICE')")
  public List<KeycloakUser> findUsers(@RequestParam(defaultValue = "") String search) {
    return keycloakUsersApi.findUsers("spring-addons", search, 20);
  }
}
