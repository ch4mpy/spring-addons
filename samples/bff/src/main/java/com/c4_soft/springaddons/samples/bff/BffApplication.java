package com.c4_soft.springaddons.samples.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * <p>
 * OAuth2 Backend For Frontend: the browser (see {@code static/index.html}) has a session on this
 * gateway and never sees a token. This gateway runs the authorization-code flow ({@code oauth2Login}),
 * keeps the tokens in session, and replaces the session cookie with the access token when routing to
 * the resource server ({@code TokenRelay} filter).
 * </p>
 * <p>
 * There is no security Java configuration: the client filter chain, with sessions, CSRF protection,
 * login, RP-Initiated Logout and Back-Channel Logout, is built by spring-addons-starter-oidc from the
 * {@code com.c4-soft.springaddons.oidc.client} properties in {@code application.yml}.
 * </p>
 */
@SpringBootApplication
public class BffApplication {

  public static void main(String[] args) {
    SpringApplication.run(BffApplication.class, args);
  }
}
