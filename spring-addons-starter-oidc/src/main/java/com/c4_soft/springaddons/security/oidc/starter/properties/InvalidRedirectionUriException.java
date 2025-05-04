package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class InvalidRedirectionUriException extends RuntimeException {
  private static final long serialVersionUID = 5011144097823445001L;

  public InvalidRedirectionUriException(URI redirectionUri) {
    super("%s doesn't match accepted post login/logout redirection URI patterns"
        .formatted(redirectionUri));
  }

}
