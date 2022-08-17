package com.c4_soft.springaddons.starter.webclient;

import java.net.URL;
import java.util.Optional;

import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;

/**
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class C4WebClientBuilderFactoryService {

	private final C4ProxySettings settings;

	public WebClient.Builder get() {
		return get(null);
	}

	public WebClient.Builder get(URL baseUrl) {
		final WebClient.Builder builder = WebClient.builder();
		Optional.ofNullable(baseUrl).map(URL::toString).ifPresent(builder::baseUrl);
		if (Boolean.FALSE.equals(settings.getEnabled()) || !StringUtils.hasText(settings.getHostname())) {
			return builder;
		}
		log.debug("Building ReactorClientHttpConnector with {}", settings);
		final ReactorClientHttpConnector connector = new ReactorClientHttpConnector(
				HttpClient.create().proxy(
						proxy -> proxy.type(settings.getType()).host(settings.getHostname()).port(settings.getPort()).username(settings.getUsername())
								.password(username -> settings.getPassword()).nonProxyHosts(settings.getNoProxy())
								.connectTimeoutMillis(settings.getConnectTimeoutMillis())));

		return builder.clientConnector(connector);
	}
}
