package com.c4_soft.springaddons.security.oauth2.config;

import java.io.Serializable;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;

public interface TokenAttributes2ClaimSetConverter<T extends Map<String, Object> & Serializable> extends Converter<Map<String, Object>, T> {

}
