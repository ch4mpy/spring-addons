package com.c4_soft.springaddons.rest;

import java.util.Optional;

import org.springframework.http.client.ClientHttpRequestInterceptor;

/**
 * Used by a {@link ClientHttpRequestInterceptor} to add a Bearer Authorization header
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface BearerProvider {
    Optional<String> getBearer();
}
