package org.cloudfoundry.credhub.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;

final public class StringUtil {

  private StringUtil() { }

  public static final Charset UTF_8 = Charset.forName("UTF-8");

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
