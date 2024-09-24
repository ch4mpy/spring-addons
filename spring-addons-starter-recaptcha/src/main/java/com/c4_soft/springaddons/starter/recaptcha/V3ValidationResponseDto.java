package com.c4_soft.springaddons.starter.recaptcha;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
public class V3ValidationResponseDto extends V2ValidationResponseDto {
	private static final long serialVersionUID = 3873084888623735286L;

	/**
	 * the score for this request (0.0 - 1.0)
	 */
	private double score;

	/**
	 * the action name for this request (important to verify)
	 */
	private String action;
}
