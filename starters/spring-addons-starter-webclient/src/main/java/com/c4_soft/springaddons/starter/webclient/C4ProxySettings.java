package com.c4_soft.springaddons.starter.webclient;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;
import reactor.netty.transport.ProxyProvider;

@Data
@Component
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.proxy")
public class C4ProxySettings {
	private ProxyProvider.Proxy type = ProxyProvider.Proxy.HTTP;
	private String hostname;
	private Short port;
	private String username;
	private String password;
	private String nonProxyHosts;
	private long connectTimeoutMillis = 10000;
}
