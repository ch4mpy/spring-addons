package com.c4_soft.springaddons.security.oauth2.config;

import java.io.Serializable;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;

public interface Jwt2ClaimSetConverter<T extends Map<String, Object> & Serializable> extends Converter<Jwt, T> {

}
