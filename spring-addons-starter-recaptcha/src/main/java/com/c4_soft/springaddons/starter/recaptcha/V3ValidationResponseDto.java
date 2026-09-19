package com.c4_soft.springaddons.starter.recaptcha;

import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * Response of the <a href="https://developers.google.com/recaptcha/docs/v3">siteverify</a>
 * endpoint for reCAPTCHA v3.
 *
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@NoArgsConstructor
public class V3ValidationResponseDto extends V2ValidationResponseDto {
  private static final long serialVersionUID = 3873084888623735286L;

  /**
   * the score for this request (0.0 - 1.0), absent when the token is not valid
   */
  private Double score;

  /**
   * the action name for this request (important to verify)
   */
  private String action;

  public V3ValidationResponseDto(boolean success, String challengeTs, String hostname,
      List<String> errorCodes, Double score, String action) {
    super(success, challengeTs, hostname, errorCodes);
    this.score = score;
    this.action = action;
  }
}
