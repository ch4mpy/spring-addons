package com.c4_soft.springaddons.security.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author ch4mp@c4-soft.com
 */
public interface SynchronizedJwt2AuthenticationConverter<T extends Authentication> extends Converter<Jwt, T> {
}