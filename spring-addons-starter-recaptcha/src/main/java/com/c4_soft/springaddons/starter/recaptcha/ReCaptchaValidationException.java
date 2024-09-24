package com.c4_soft.springaddons.starter.recaptcha;

/**
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
public class ReCaptchaValidationException extends RuntimeException {
	private static final long serialVersionUID = 6903170315686842893L;

	public ReCaptchaValidationException(String message) {
		super(message);
	}

}
