package com.c4_soft.springaddons.security.oidc.starter;

import java.util.List;
import java.util.Map;

import com.c4_soft.springaddons.security.oidc.starter.properties.SimpleAuthoritiesMappingProperties;

public interface AuthoritiesMappingPropertiesResolver {
    List<SimpleAuthoritiesMappingProperties> resolve(Map<String, Object> claimSet);
}
