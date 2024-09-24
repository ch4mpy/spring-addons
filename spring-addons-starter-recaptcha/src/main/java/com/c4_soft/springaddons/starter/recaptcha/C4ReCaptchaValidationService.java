package com.c4_soft.springaddons.starter.recaptcha;

import java.util.stream.Collectors;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import com.c4_soft.springaddons.rest.SpringAddonsRestClientSupport;

import lombok.extern.slf4j.Slf4j;

/**
 * Usage:
 *
 * <pre>
 * if (Boolean.FALSE.equals(captcha.checkV2(reCaptcha).block())) {
 *     throw new RuntimeException("Are you a robot?");
 * }
 * </pre>
 *
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Service
@Slf4j
public class C4ReCaptchaValidationService {

    private final RestClient client;
    private final String googleRecaptchaSecret;
    private final double v3Threshold;

    public C4ReCaptchaValidationService(C4ReCaptchaSettings settings, SpringAddonsRestClientSupport clientSupport) {
        this.client = clientSupport.client().baseUrl(settings.getSiteverifyUrl().toString()).build();
        this.googleRecaptchaSecret = settings.getSecretKey();
        this.v3Threshold = settings.getV3Threshold();
    }

    /**
     * Checks a reCaptcha V2 challenge response
     *
     * @param response answer provided by the client
     * @return true / false
     */
    public Boolean checkV2(String response) {
        final var dto = response(response, V2ValidationResponseDto.class);
        log.debug("reCaptcha result : {}", dto);
        return dto.isSuccess();
    }

    /**
     * Checks a reCaptcha V3 challenge response
     *
     * @param response answer provided by the client
     * @return a score between 0 and 1
     * @throws ReCaptchaValidationException if response wasn't a valid reCAPTCHA token for your site or score is below configured threshold
     */
    public Double checkV3(String response) throws ReCaptchaValidationException {
        final var dto = response(response, V3ValidationResponseDto.class);
        log.debug("reCaptcha result : {}", dto);
        if (!dto.isSuccess()) {
            throw new ReCaptchaValidationException(
                String.format("Failed to validate reCaptcha: %s %s", response, dto.getErrorCodes().stream().collect(Collectors.joining("[", ", ", "]"))));
        }
        if (dto.getScore() < v3Threshold) {
            throw new ReCaptchaValidationException(String.format("Failed to validate reCaptcha: %s. Score is %f", response, dto.getScore()));
        }
        return dto.getScore();
    }

    private <T> T response(String response, Class<T> dtoType) {
        final var formData = new LinkedMultiValueMap<>();
        formData.add("secret", googleRecaptchaSecret);
        formData.add("response", response);
        return client.post().contentType(MediaType.APPLICATION_FORM_URLENCODED).body(formData).retrieve().toEntity(dtoType).getBody();
    }
}
