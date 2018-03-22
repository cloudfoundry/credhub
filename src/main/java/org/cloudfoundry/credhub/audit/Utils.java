package org.cloudfoundry.credhub.audit;

public class Utils {
  public static String getResultCode(int statusCode) {
    if (statusCode <= 199) {
      return "info";
    } else if (statusCode <= 299) {
      return "success";
    } else if (statusCode <= 399) {
      return "redirect";
    } else if (statusCode <= 499) {
      return "clientError";
    } else {
      return "serverError";
    }
  }
}
