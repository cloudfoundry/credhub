package org.cloudfoundry.credhub.util;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

public class StringUtil {

  public static final Charset UTF_8 =Charset.forName("UTF-8");

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
