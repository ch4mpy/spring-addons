package com.c4_soft.springaddons.starter.webclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class NoPropertiesTest {

	@Autowired
	C4ProxySettings settings;

	@Autowired
	C4WebClientBuilderFactoryService service;

	@Test
	void testSettings() {
		assertEquals(10000, settings.getConnectTimeoutMillis());
		assertNull(settings.getEnabled());
		assertNull(settings.getHostname());
		assertNull(settings.getNoProxy());
		assertNull(settings.getPassword());
		assertNull(settings.getPort());
		assertNull(settings.getType());
		assertNull(settings.getUsername());
	}

	@Test
	void testService() {
		final var actual = service.get();
		assertNotNull(actual);
	}

}
