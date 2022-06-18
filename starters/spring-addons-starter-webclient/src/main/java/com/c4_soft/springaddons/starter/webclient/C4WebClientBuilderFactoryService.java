package com.c4_soft.springaddons.starter.webclient;

import java.net.InetSocketAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
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

	private final Map<InetSocketAddress, ReactorClientHttpConnector> httpConnectors = new HashMap<>();

	public WebClient.Builder get(URL baseUrl) {
		return WebClient.builder().baseUrl(baseUrl.toString()).clientConnector(getConnector(new InetSocketAddress(baseUrl.getHost(), baseUrl.getPort())));
	}

	private ReactorClientHttpConnector getConnector(InetSocketAddress addr) {
		return httpConnectors.computeIfAbsent(addr, a -> {
			log.debug("Building ReactorClientHttpConnector for {} with {}", addr.getHostName(), settings);
			return new ReactorClientHttpConnector(
					HttpClient
							.create()
							.proxy(
									proxy -> proxy
											.type(settings.getType())
											.address(addr)
											.username(settings.getUsername())
											.password(username -> settings.getPassword())
											.nonProxyHosts(settings.getNonProxyHosts())
											.connectTimeoutMillis(settings.getConnectTimeoutMillis())));
		});
	}
}
