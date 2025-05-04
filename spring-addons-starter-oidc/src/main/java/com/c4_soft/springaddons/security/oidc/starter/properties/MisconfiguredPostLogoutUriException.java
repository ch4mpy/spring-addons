package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.Collection;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class MisconfiguredPostLogoutUriException extends RuntimeException {
  private static final long serialVersionUID = 244159916740008306L;

  public MisconfiguredPostLogoutUriException(URI redirectionUri,
      Collection<Pattern> allowedPatterns) {
    super("%s does not patch allowed post-logout patterns %s".formatted(redirectionUri,
        allowedPatterns.stream().map(Pattern::toString)
            .collect(Collectors.joining("/; /", "[/", "/]"))));
  }

}
