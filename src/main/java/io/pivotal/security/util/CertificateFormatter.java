package io.pivotal.security.util;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.Serializable;
import java.io.StringWriter;

public class CertificateFormatter {
  public static String pemOf(Serializable pemObject) throws IOException {
    StringWriter sw = new StringWriter();
    org.bouncycastle.openssl.jcajce.JcaPEMWriter writer = new JcaPEMWriter(sw);
    writer.writeObject(pemObject);
    writer.close();
    return sw.toString();
  }
}