package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ProxiesAuth.Proxy;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class })
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	// @formatter:off
	@Test
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isUnauthorized());
	}

	@Test
	void givenRequestIsAnonymous_whenGreetPublic_thenOk() throws Exception {
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
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@ProxiesAuth(authorities = { "AUTHOR" })
	void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isForbidden());
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
	void givenUserIsNotGrantedWithNiceButHasProxyForGreetedUser_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/ch4mpy")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR", "NICE" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsGrantedWithNice_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/ch4mpy")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "jwacongne", can = { "greet" }) })
	void givenUserIsNotGrantedWithNiceAndHasNoProxyForGreetedUser_whenGreetOnBehalfOf_thenForbidden() throws Exception {
		mockMvc.get("/greet/on-behalf-of/greeted")
			.andExpect(status().isForbidden());
	}

	@Test
	@ProxiesAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsGreetingHimself_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate from Tonton Pirate!"));
	}
	// @formatter:on
}
