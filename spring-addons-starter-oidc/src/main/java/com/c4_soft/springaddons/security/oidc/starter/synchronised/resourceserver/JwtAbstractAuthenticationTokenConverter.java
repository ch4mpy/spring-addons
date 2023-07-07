package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

public interface JwtAbstractAuthenticationTokenConverter extends Converter<Jwt, AbstractAuthenticationToken> {

}
