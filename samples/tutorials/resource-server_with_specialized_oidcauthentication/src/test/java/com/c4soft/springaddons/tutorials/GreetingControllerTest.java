package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureSecurityAddons;
import com.c4soft.springaddons.tutorials.ProxiesAuth.Proxy;

@WebMvcTest(GreetingController.class)
@AutoConfigureSecurityAddons
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvc mockMvc;

	// @formatter:off
	@Test
	@ProxiesAuth(
		authorities = { "NICE_GUY", "AUTHOR" },
		claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
		proxies = {
			@Proxy(onBehalfOf = "machin", can = { "truc", "bidule" }),
			@Proxy(onBehalfOf = "chose") })
	void whenNiceGuyThenCanBeGreeted() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@ProxiesAuth(authorities = { "AUTHOR" })
	void whenNotNiceGuyThenForbiddenToBeGreeted() throws Exception {
		mockMvc.perform(get("/greet").secure(true)).andExpect(status().isForbidden());
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "greeted", can = { "greet" }) })
	void whenNotNiceWithProxyThenCanGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isOk()).andExpect(content().string("Hi greeted!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR", "ROLE_NICE_GUY" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"))
	void whenNiceWithoutProxyThenCanGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isOk()).andExpect(content().string("Hi greeted!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
	void whenNotNiceWithoutRequiredProxyThenForbiddenToGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isForbidden());
	}
	// @formatter:on
}
