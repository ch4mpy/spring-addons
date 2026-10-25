package com.c4_soft.springaddons.security.oidc.starter.properties;

/**
 * Thrown by the authorization request resolvers when a post-login success or failure URI provided
 * by the user-agent does not match {@code post-login-allowed-uri-patterns}. Distinct from the
 * post-logout refusals (plain {@link InvalidRedirectionUriException}) so that the client
 * filter-chain can answer it with a {@code 400} without catching those.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class InvalidPostLoginUriException extends InvalidRedirectionUriException {
  private static final long serialVersionUID = -1880935950395010262L;

  public InvalidPostLoginUriException(String redirectionUri) {
    super(redirectionUri);
  }
}
