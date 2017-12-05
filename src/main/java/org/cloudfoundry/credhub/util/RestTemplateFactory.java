package org.cloudfoundry.credhub.util;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;

@Component
public class RestTemplateFactory {
  public RestTemplate createRestTemplate(
      String trustStorePath,
      String trustStorePassword
  ) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
    File trustStore = new File(trustStorePath);
    SSLContext sslContext = new SSLContextBuilder()
        .loadTrustMaterial(trustStore, trustStorePassword.toCharArray())
        .build();
    SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
    HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);

    return new RestTemplate(requestFactory);
  }
}
