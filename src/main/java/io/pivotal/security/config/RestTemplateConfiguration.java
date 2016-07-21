package io.pivotal.security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@Configuration
public class RestTemplateConfiguration {

  @Bean
  @ConditionalOnProperty(prefix = "auth-server", name = "skip-ssl-validation", havingValue = "false", matchIfMissing = true)
  RestTemplate remoteTokenServicesRestTemplate() {
    return new RestTemplate();
  }

  @Bean(name = "remoteTokenServicesRestTemplate")
  @ConditionalOnProperty(prefix = "auth-server", name = "skip-ssl-validation")
  RestTemplate lenientRemoteTokenServicesRestTemplate() throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext ctx = SSLContext.getInstance("TLS");
    X509TrustManager tm = new X509TrustManager() {

      public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
      }

      public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
      }

      public X509Certificate[] getAcceptedIssuers() {
        return null;
      }
    };
    ctx.init(null, new TrustManager[] { tm }, null);

    return new RestTemplate(new SimpleClientHttpRequestFactory() {
      @Override
      protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
        super.prepareConnection(connection, httpMethod);
        if (connection instanceof HttpsURLConnection) {
          ((HttpsURLConnection) connection).setHostnameVerifier((s, sslSession) -> true);
          ((HttpsURLConnection) connection).setSSLSocketFactory(ctx.getSocketFactory());
        }
      }
    });
  }
}
