package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface ServerHttpSecurityPostProcessor {
	HttpSecurity process(HttpSecurity httpSecurity) throws Exception;
}
