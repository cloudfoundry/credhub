package org.cloudfoundry.credhub;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;

import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

@Component
public class RestTemplateFactory {
  public RestTemplate createRestTemplate(
    final String trustStorePath,
    final String trustStorePassword
  ) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
    final File trustStore = new File(trustStorePath);
    final SSLContext sslContext = new SSLContextBuilder()
      .loadTrustMaterial(trustStore, trustStorePassword.toCharArray())
      .build();
    final SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
    final HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    final HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);

    return new RestTemplate(requestFactory);
  }
}
