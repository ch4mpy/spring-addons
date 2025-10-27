package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithOAuthenticationApplicationTests {
	@Autowired
	MockMvcSupport api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGreet_thenForbidden() throws Exception {
		api.get("/greet").andExpect(status().isForbidden());
	}

	// @formatter:off
    @Test
    @WithOpaqueToken("ch4mp.json")
    void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
        api.get("/greet")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.body").value("Hi ch4mp! You are granted with: [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL]."));
    }
    // @formatter:on

}
