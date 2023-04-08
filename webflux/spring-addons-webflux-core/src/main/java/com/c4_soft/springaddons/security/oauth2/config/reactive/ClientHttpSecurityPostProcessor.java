package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface ClientHttpSecurityPostProcessor {
    ServerHttpSecurity process(ServerHttpSecurity serverHttpSecurity);
}