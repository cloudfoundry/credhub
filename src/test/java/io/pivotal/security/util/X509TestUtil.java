package io.pivotal.security.util;

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class X509TestUtil {
  public static X509Certificate cert(String string) throws CertificateException, NoSuchProviderException {
    return (X509Certificate) CertificateFactory
        .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
        .generateCertificate(new ByteArrayInputStream(string.getBytes()));
  }

}
