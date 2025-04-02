package org.cloudfoundry.credhub

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.client5.http.ssl.TlsSocketStrategy
import org.apache.hc.core5.ssl.SSLContextBuilder
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.stereotype.Component
import org.springframework.web.client.RestTemplate
import java.io.File
import java.io.IOException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException

@Component
class RestTemplateFactory {
    @Throws(
        CertificateException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        IOException::class,
        KeyManagementException::class,
    )
    fun createRestTemplate(
        trustStorePath: String,
        trustStorePassword: String,
    ): RestTemplate {
        val trustStore = File(trustStorePath)
        val sslContext =
            SSLContextBuilder()
                .loadTrustMaterial(trustStore, trustStorePassword.toCharArray())
                .build()
        val tlsSocketStrategy: TlsSocketStrategy =
            ClientTlsStrategyBuilder
                .create()
                .setSslContext(sslContext)
                .build() as TlsSocketStrategy

        val httpClient =
            HttpClientBuilder
                .create()
                .setConnectionManager(
                    PoolingHttpClientConnectionManagerBuilder
                        .create()
                        .setTlsSocketStrategy(tlsSocketStrategy)
                        .build(),
                ).build()

        val requestFactory = HttpComponentsClientHttpRequestFactory(httpClient)

        return RestTemplate(requestFactory)
    }
}
