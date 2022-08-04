package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface SynchronizedJwt2AuthenticationConverter<T extends Authentication> extends Converter<Jwt, T> {
}