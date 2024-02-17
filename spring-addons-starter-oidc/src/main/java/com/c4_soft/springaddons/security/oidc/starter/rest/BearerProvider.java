package com.c4_soft.springaddons.security.oidc.starter.rest;

import java.util.Optional;

public interface BearerProvider {
    Optional<String> getBearer();
}