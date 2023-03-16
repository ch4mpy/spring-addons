package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

/**
 * Configurable converter from token claims to spring authorities
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface OAuth2AuthoritiesConverter extends Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> {
}