package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureAddonsWebSecurity;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4soft.springaddons.tutorials.ProxiesAuth.Proxy;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class })
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	// @formatter:off
	@Test
	void whenAnonymousThenUnauthorizedToGreet() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isUnauthorized());
	}

	@Test
	void whenAnonymousThenCanGetPublicGreeting() throws Exception {
		mockMvc.get("/greet/public")
			.andExpect(status().isOk())
			.andExpect(content().string("Hello world"));
	}

	@Test
	@ProxiesAuth(
		authorities = { "NICE", "AUTHOR" },
		claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
		proxies = {
			@Proxy(onBehalfOf = "machin", can = { "truc", "bidule" }),
			@Proxy(onBehalfOf = "chose") })
	void whenNiceGuyThenCanBeGreeted() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@ProxiesAuth(authorities = { "AUTHOR" })
	void whenNotNiceGuyThenForbiddenToBeGreeted() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isForbidden());
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
	void whenNotNiceWithProxyThenCanGreetFor() throws Exception {
		mockMvc.get("/greet/on-behalf-of/ch4mpy")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR", "NICE" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenNiceWithoutProxyThenCanGreetFor() throws Exception {
		mockMvc.get("/greet/on-behalf-of/ch4mpy")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "jwacongne", can = { "greet" }) })
	void whenNotNiceWithoutRequiredProxyThenForbiddenToGreetFor() throws Exception {
		mockMvc.get("/greet/on-behalf-of/greeted")
			.andExpect(status().isForbidden());
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenHimselfThenCanGreetFor() throws Exception {
		mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate from Tonton Pirate!"));
	}
	// @formatter:on
}
