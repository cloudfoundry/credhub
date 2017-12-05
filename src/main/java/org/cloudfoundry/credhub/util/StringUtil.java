package org.cloudfoundry.credhub.util;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {

  public static final Charset UTF_8 =Charset.forName("UTF-8");


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

  public static String fromInputStream(InputStream requestBody) throws IOException {
    ByteSource requestByteSource = new ByteSource() {
      @Override
      public InputStream openStream() throws IOException {
        return requestBody;
      }
    };

    return requestByteSource.asCharSource(Charsets.UTF_8).read();
  }
}
