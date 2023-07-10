package com.c4_soft.springaddons.security.oidc.starter.properties;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class MissingAuthorizationServerConfigurationException extends RuntimeException {
    private static final long serialVersionUID = 5189849969622154264L;

    public MissingAuthorizationServerConfigurationException(String jwtIssuer) {
        super("Check application properties: %s is not a trusted issuer".formatted(jwtIssuer));
    }

}
