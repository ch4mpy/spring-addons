package com.c4_soft.springaddons.rest;

import org.springframework.web.reactive.function.client.ClientRequest;
import reactor.core.publisher.Mono;

public interface ReactiveBearerProvider {
  Mono<String> getBearer(ClientRequest request);
}
