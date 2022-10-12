package ${package}.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import ${package}.ControllerTest;
import ${package}.domain.SampleEntity;
import ${package}.r2dbc.SampleEntityRepository;
import ${package}.web.dtos.SampleEditDto;
import ${package}.web.dtos.SampleResponseDto;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;
import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@WebFluxTest(SampleController.class)
@ControllerTest
@Import({ SampleMapperImpl.class })
class SampleControllerTest {
	SampleEntity sampleEntity1;
	SampleEntity sampleEntity42;

	final ObjectMapper json = new ObjectMapper();

	@Autowired
	WebTestClientSupport rest;

	@MockBean
	SampleEntityRepository sampleEntityRepository;

	@BeforeEach
	public void before() {
		sampleEntity1 = new SampleEntity(1L, "Sample label 1");
		sampleEntity42 = new SampleEntity(42L, "Sample label 42");
		when(sampleEntityRepository.findById(1L)).thenReturn(Mono.just(sampleEntity1));
		when(sampleEntityRepository.findById(42L)).thenReturn(Mono.just(sampleEntity42));
		when(sampleEntityRepository.findAll()).thenReturn(Flux.fromArray(new SampleEntity[] { sampleEntity1, sampleEntity42 }));
	}

	@Test
	void whenRetrieveAllWithoutAuthThenUnauthenticated() throws Exception {
		rest.get("https://localhost/${api-path}").expectStatus().isUnauthorized();
	}

	@Test
	@OpenId()
	void whenRetrieveAllWithAuthThenOk() throws Exception {
		rest.get("https://localhost/${api-path}").expectStatus().isOk().expectBodyList(SampleResponseDto.class).hasSize(2);
	}

	@Test
	@OpenId()
	void whenPostValidSampleEditDtoThenAccepted() throws Exception {
		when(sampleEntityRepository.save(any())).thenReturn(Mono.just(sampleEntity42));

		rest.post(new SampleEditDto("Edited label"), "https://localhost/${api-path}").expectStatus().isCreated();
	}

	@Test
	@OpenId()
	void whenPutValidSampleEditDtoAtValidIdThenAccepted() throws Exception {
		when(sampleEntityRepository.save(any())).thenReturn(Mono.just(sampleEntity42));

		rest.put(new SampleEditDto("Edited label"), "https://localhost/${api-path}/{id}", sampleEntity42.getId()).expectStatus().isAccepted();
	}
}
