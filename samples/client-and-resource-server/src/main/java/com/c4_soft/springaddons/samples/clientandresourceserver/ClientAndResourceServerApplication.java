package com.c4_soft.springaddons.samples.clientandresourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * <p>
 * One application, two security filter chains, both auto-configured by spring-addons-starter-oidc
 * from {@code application.yml}:
 * </p>
 * <ul>
 * <li>a <b>client</b> chain ({@code @Order(LOWEST_PRECEDENCE - 1)}) with sessions, CSRF protection,
 * {@code oauth2Login} and RP-Initiated Logout, intercepting exactly the routes listed in
 * {@code com.c4-soft.springaddons.oidc.client.security-matchers}: the UI and the login / logout
 * endpoints. Unauthorized requests are redirected to login.</li>
 * <li>a <b>resource server</b> chain ({@code @Order(LOWEST_PRECEDENCE)}) with no session, no CSRF
 * protection and a 401 for unauthorized requests. It declares no security matcher, so it processes
 * everything the client chain did not: the REST API under {@code /api/**}.</li>
 * </ul>
 * <p>
 * The two chains are what makes this scenario work: their requirements are irreconcilable (a session
 * cookie needs CSRF protection, a Bearer token does not and the API must stay stateless), so they
 * cannot be a single chain, and the order plus the security matchers decide which one applies.
 * </p>
 */
@SpringBootApplication
@EnableMethodSecurity
public class ClientAndResourceServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(ClientAndResourceServerApplication.class, args);
  }
}
