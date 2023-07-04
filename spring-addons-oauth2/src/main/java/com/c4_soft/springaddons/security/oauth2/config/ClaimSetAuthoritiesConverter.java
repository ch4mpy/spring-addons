package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

public interface ClaimSetAuthoritiesConverter extends Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> {

}
