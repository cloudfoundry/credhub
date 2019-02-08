package org.cloudfoundry.credhub.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;

final public class StringUtil {

  public static final Charset UTF_8 = Charset.forName("UTF-8");

  private StringUtil() {
    super();
  }

  public static String fromInputStream(final InputStream requestBody) throws IOException {
    final ByteSource requestByteSource = new ByteSource() {
      @Override
      public InputStream openStream() throws IOException {
        return requestBody;
      }
    };

    return requestByteSource.asCharSource(Charsets.UTF_8).read();
  }
}
