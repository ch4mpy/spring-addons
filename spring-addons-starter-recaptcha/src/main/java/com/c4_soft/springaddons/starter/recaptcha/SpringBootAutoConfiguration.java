package com.c4_soft.springaddons.starter.recaptcha;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import({ ReCaptchaSettings.class, ReCaptchaValidationService.class })
public class SpringBootAutoConfiguration {

}
