package com.c4_soft.springaddons.starter.recaptcha;

import java.io.Serializable;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response of the <a href="https://developers.google.com/recaptcha/docs/verify">siteverify</a>
 * endpoint for reCAPTCHA v2.
 *
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@NoArgsConstructor
public class V2ValidationResponseDto implements Serializable {
  private static final long serialVersionUID = -5003891633297808293L;

  /**
   * whether this request was a valid reCAPTCHA token for your site
   */
  private boolean success;

  /**
   * timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
   */
  @JsonProperty("challenge_ts")
  private String challengeTs;

  /**
   * the hostname of the site where the reCAPTCHA was solved
   */
  private String hostname;

  /**
   * optional
   */
  @JsonProperty("error-codes")
  private List<String> errorCodes = List.of();

  public V2ValidationResponseDto(boolean success, String challengeTs, String hostname,
      List<String> errorCodes) {
    this.success = success;
    this.challengeTs = challengeTs;
    this.hostname = hostname;
    setErrorCodes(errorCodes);
  }

  /**
   * @param errorCodes never null (empty when absent from the response)
   */
  public void setErrorCodes(List<String> errorCodes) {
    this.errorCodes = errorCodes == null ? List.of() : List.copyOf(errorCodes);
  }
}
