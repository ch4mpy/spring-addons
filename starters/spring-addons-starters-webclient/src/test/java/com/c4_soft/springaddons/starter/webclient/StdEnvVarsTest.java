package com.c4_soft.springaddons.starter.webclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import reactor.netty.transport.ProxyProvider;

@SpringBootTest
@ActiveProfiles("std-env-vars")
class StdEnvVarsTest {

	@Autowired
	C4ProxySettings settings;

	@Autowired
	C4WebClientBuilderFactoryService service;

	@Test
	void testSettings() {
		assertEquals(10000, settings.getConnectTimeoutMillis());
		assertNull(settings.getEnabled());
		assertEquals("env-proxy", settings.getHostname());
		assertEquals("(localhost)|(bravo\\-ch4mp)|(.*\\.env\\-domain\\.pf)", settings.getNoProxy());
		assertEquals("truc", settings.getPassword());
		assertEquals(8080, settings.getPort());
		assertEquals(ProxyProvider.Proxy.HTTP, settings.getType());
		assertEquals("machin", settings.getUsername());
	}

	@Test
	void testService() {
		final var actual = service.get();
		assertNotNull(actual);
	}

}
