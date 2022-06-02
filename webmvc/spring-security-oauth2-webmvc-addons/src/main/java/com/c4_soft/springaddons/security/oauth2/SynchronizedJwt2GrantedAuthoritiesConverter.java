package com.c4_soft.springaddons.security.oauth2;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public interface SynchronizedJwt2GrantedAuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {

}
