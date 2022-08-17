package com.c4_soft.springaddons.starter.webclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.transport.ProxyProvider;

@SpringBootTest
@ActiveProfiles("addons")
class AddonsTest {

	@Autowired
	C4ProxySettings settings;

	@Autowired
	C4WebClientBuilderFactoryService service;

	@Test
	void testSettings() {
		assertEquals(500, settings.getConnectTimeoutMillis());
		assertNull(settings.getEnabled());
		assertEquals("corp-proxy", settings.getHostname());
		assertEquals("(localhost)|(bravo\\-ch4mp)|(.*\\.corporate\\-domain\\.com)", settings.getNoProxy());
		assertEquals("abracadabra", settings.getPassword());
		assertEquals(8080, settings.getPort());
		assertEquals(ProxyProvider.Proxy.SOCKS5, settings.getType());
		assertEquals("toto", settings.getUsername());
	}

	@Test
	void testService() {
		final WebClient.Builder actual = service.get();
		assertNotNull(actual);
	}

}
