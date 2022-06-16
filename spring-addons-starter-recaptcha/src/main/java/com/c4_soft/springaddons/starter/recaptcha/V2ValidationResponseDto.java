package com.c4_soft.springaddons.starter.recaptcha;

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class V2ValidationResponseDto implements Serializable {
	private static final long serialVersionUID = -5003891633297808293L;

	/**
	 * whether this request was a valid reCAPTCHA token for your site
	 */
	private boolean success;

	/**
	 * timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
	 */
	private String challengeTs;

	/**
	 * the hostname of the site where the reCAPTCHA was solved
	 */
	private String hostname;

	/**
	 * optional
	 */
	private List<String> errorCodes;

}
