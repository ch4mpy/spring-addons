package com.c4_soft.springaddons.starter.recaptcha;

import java.util.stream.Collectors;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Usage:
 *
 * <pre>
 * if (Boolean.FALSE.equals(captcha.checkV2(reCaptcha).block())) {
 * 	throw new RuntimeException("Are you a robot?");
 * }
 * </pre>
 *
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReCaptchaValidationService {

	private final ReCaptchaSettings settings;
	private WebClient webClient;

	/**
	 * Checks a reCaptcha V2 challenge response
	 *
	 * @param  response answer provided by the client
	 * @return          true / false
	 */
	public Mono<Boolean> checkV2(String response) {
		return webClient()
				.post()
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData("secret", settings.getSecret()).with("response", response))
				.retrieve()
				.bodyToMono(V2ValidationResponseDto.class)
				.map(dto -> {
					log.debug("reCaptcha result : {}", dto);
					return dto.isSuccess();
				});
	}

	/**
	 * Checks a reCaptcha V3 challenge response
	 *
	 * @param  response                     answer provided by the client
	 * @return                              a score between 0 and 1
	 * @throws ReCaptchaValidationException if response wasn't a valid reCAPTCHA token for your site or score is below configured threshold
	 */
	public Mono<Double> checkV3(String response) throws ReCaptchaValidationException {
		return webClient()
				.post()
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData("secret", settings.getSecret()).with("response", response))
				.retrieve()
				.bodyToMono(V3ValidationResponseDto.class)
				.map(dto -> {
					log.debug("reCaptcha result : {}", dto);
					if (!dto.isSuccess()) {
						throw new ReCaptchaValidationException(
								String
										.format(
												"Failed to validate reCaptcha: %s %s",
												response,
												dto.getErrorCodes().stream().collect(Collectors.joining("[", ", ", "]"))));
					}
					if (dto.getScore() < settings.getV3Threshold()) {
						throw new ReCaptchaValidationException(String.format("Failed to validate reCaptcha: %s. Score is %f", response, dto.getScore()));
					}
					return dto.getScore();
				});
	}

	private WebClient webClient() {
		if (webClient == null) {
			webClient = WebClient.builder().baseUrl(settings.getSiteverifyUrl().toString()).build();
		}
		return webClient;
	}
}
