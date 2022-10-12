package ${package};

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import ${package}.web.dtos.SampleEditDto;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class SampleApiTest {

	@Autowired
	MockMvcSupport api;

	@Test
	void whenRetrieveAllWithoutAuthThenUnauthenticated() throws Exception {
		api.get("/${api-path}").andExpect(status().isUnauthorized());
	}

	@Test
	@OpenId()
	void whenAuthenticatedThenCanCreateUpdateRetrieve() throws Exception {
		api.get("/${api-path}").andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));

		api.post(new SampleEditDto("First label"), "/${api-path}").andExpect(status().isCreated());
		api.post(new SampleEditDto("Second label"), "/${api-path}").andExpect(status().isCreated());
		api.get("/${api-path}").andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
		api.get("/${api-path}/1").andExpect(status().isOk()).andExpect(jsonPath("$.mappedLabel", equalTo("First label")));
		api.get("/${api-path}/2").andExpect(status().isOk()).andExpect(jsonPath("$.mappedLabel", equalTo("Second label")));

		api.put(new SampleEditDto("Edited label"), "/${api-path}/{id}", 1L).andExpect(status().isAccepted());
		api.get("/${api-path}").andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
		api.get("/${api-path}/1").andExpect(status().isOk()).andExpect(jsonPath("$.mappedLabel", equalTo("Edited label")));
	}

}
