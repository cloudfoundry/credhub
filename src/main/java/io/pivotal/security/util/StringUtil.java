package io.pivotal.security.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {

  public static final String INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS = "[*]";
  private static Pattern JSON_ARRAY_REF = Pattern.compile("(.*)\\[\\d+\\](.*)");

  public static String convertJsonArrayRefToWildcard(String jsonPath) {
    String result = jsonPath;
    Matcher matcher = JSON_ARRAY_REF.matcher(jsonPath);
    if (matcher.matches()) {
      result = matcher.group(1) + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS + matcher.group(2);
    }
    return result;
  }
}
