package com.c4_soft.springaddons.rest;

import reactor.core.publisher.Mono;

public interface ReactiveBearerProvider {
    Mono<String> getBearer();
}
