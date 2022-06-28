package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface HttpSecurityPostProcessor {
	HttpSecurity process(HttpSecurity httpSecurity);
}
