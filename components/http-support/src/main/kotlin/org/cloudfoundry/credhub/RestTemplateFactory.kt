package org.cloudfoundry.credhub

import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
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
        val socketFactory = SSLConnectionSocketFactory(sslContext)
        val httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build()
        val requestFactory = HttpComponentsClientHttpRequestFactory(httpClient)

        return RestTemplate(requestFactory)
    }
}
