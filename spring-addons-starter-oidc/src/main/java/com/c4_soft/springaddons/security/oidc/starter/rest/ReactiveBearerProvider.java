package com.c4_soft.springaddons.security.oidc.starter.rest;

import reactor.core.publisher.Mono;

public interface ReactiveBearerProvider {
    Mono<String> getBearer();
}
