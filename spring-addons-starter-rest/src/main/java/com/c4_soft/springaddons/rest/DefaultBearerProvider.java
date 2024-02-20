package com.c4_soft.springaddons.rest;

import java.util.Optional;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class DefaultBearerProvider implements BearerProvider {

    @Override
    public Optional<String> getBearer() {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwt) {
            return Optional.of(jwt.getToken().getTokenValue());
        }
        if (authentication instanceof BearerTokenAuthentication opaque) {
            return Optional.of(opaque.getToken().getTokenValue());
        }
        return Optional.empty();
    }

}
