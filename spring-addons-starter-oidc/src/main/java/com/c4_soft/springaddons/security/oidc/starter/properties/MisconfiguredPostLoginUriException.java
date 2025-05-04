package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.Collection;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class MisconfiguredPostLoginUriException extends RuntimeException {
  private static final long serialVersionUID = -2294844735831156498L;

  public MisconfiguredPostLoginUriException(URI redirectionUri,
      Collection<Pattern> allowedPatterns) {
    super(
        "%s does not patch allowed post-login patterns %s".formatted(redirectionUri, allowedPatterns
            .stream().map(Pattern::toString).collect(Collectors.joining("/; /", "[/", "/]"))));
  }

}
