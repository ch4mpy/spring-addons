package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public interface OAuth2AuthenticationFactory {
	AbstractAuthenticationToken build(String bearerString, Map<String, Object> claims);
}
