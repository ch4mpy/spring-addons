package com.c4_soft.springaddons.security.oauth2.config;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

public interface ClaimSet2AuthoritiesConverter<T extends Map<String, Object> & Serializable> extends Converter<T, Collection<? extends GrantedAuthority>> {

}
