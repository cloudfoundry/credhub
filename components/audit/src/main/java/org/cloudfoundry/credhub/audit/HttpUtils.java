package org.cloudfoundry.credhub.audit;

import org.springframework.http.HttpStatus;

final public class HttpUtils {
  private HttpUtils() {
    super();
  }

  public static String getResultCode(final int statusCode) {
    if (statusCode < HttpStatus.OK.value()) {
      return "info";
    } else if (statusCode < HttpStatus.MULTIPLE_CHOICES.value()) {
      return "success";
    } else if (statusCode < HttpStatus.BAD_REQUEST.value()) {
      return "redirect";
    } else if (statusCode < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
      return "clientError";
    } else {
      return "serverError";
    }
  }
}
