package com.c4_soft.springaddons.starter.webclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootTest
@ActiveProfiles({ "std-env-vars", "disabled-proxy" })
class StdEnvVarsDisabledProxyTest {

	@Autowired
	C4ProxySettings settings;

	@Autowired
	C4WebClientBuilderFactoryService service;

	@Test
	void testSettings() {
		assertEquals(10000, settings.getConnectTimeoutMillis());
		assertEquals(Boolean.FALSE, settings.getEnabled());
		assertNull(settings.getHostname());
		assertNull(settings.getNoProxy());
		assertNull(settings.getPassword());
		assertNull(settings.getPort());
		assertNull(settings.getType());
		assertNull(settings.getUsername());
	}

	@Test
	void testService() {
		final WebClient.Builder actual = service.get();
		assertNotNull(actual);
	}

}
