package com.c4_soft.springaddons.security.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import reactor.core.publisher.Flux;

public interface ReactiveJwt2GrantedAuthoritiesConverter extends Converter<Jwt, Flux<GrantedAuthority>> {

}
