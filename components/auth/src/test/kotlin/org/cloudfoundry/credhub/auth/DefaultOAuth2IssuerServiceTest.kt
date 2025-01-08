package org.cloudfoundry.credhub.auth

import org.cloudfoundry.credhub.RestTemplateFactory
import org.cloudfoundry.credhub.config.OAuthProperties
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.util.HashMap

@RunWith(JUnit4::class)
class DefaultOAuth2IssuerServiceTest {
    private var subject: DefaultOAuth2IssuerService? = null

    private var restTemplate: RestTemplate? = null

    @Before
    @Throws(
        URISyntaxException::class,
        CertificateException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        IOException::class,
        KeyManagementException::class,
    )
    fun setUp() {
        val trustStore = "test-trust-store"
        val trustStorePassword = "test-trust-store-password"

        val oAuthProperties = OAuthProperties()
        oAuthProperties.trustStore = trustStore
        oAuthProperties.trustStorePassword = trustStorePassword
        oAuthProperties.url = AUTH_SERVER

        val restTemplateFactory = mock(RestTemplateFactory::class.java)
        restTemplate = mock(RestTemplate::class.java)

        `when`(restTemplateFactory.createRestTemplate(trustStore, trustStorePassword))
            .thenReturn(restTemplate)

        subject = DefaultOAuth2IssuerService(restTemplateFactory, oAuthProperties)
    }

    @Test
    @Throws(URISyntaxException::class)
    fun fetchIssuer_setsAndUpdatesTheIssuer() {
        val issuer1 = "first-issuer"
        val issuer2 = "second-issuer"

        val uaaResponseBody = HashMap<String, String>()
        val authServerUri = URI("$AUTH_SERVER/.well-known/openid-configuration")
        val uaaResponse = ResponseEntity(uaaResponseBody as HashMap<*, *>, HttpStatus.OK)

        uaaResponseBody["issuer"] = issuer1

        `when`(restTemplate!!.getForEntity(authServerUri, HashMap::class.java)).thenReturn(uaaResponse)

        subject!!.fetchIssuer()

        assertThat<String>(subject!!.getIssuer(), equalTo(issuer1))

        uaaResponseBody.clear()
        uaaResponseBody["issuer"] = issuer2

        assertThat<String>(subject!!.getIssuer(), equalTo(issuer1))

        subject!!.fetchIssuer()

        assertThat<String>(subject!!.getIssuer(), equalTo(issuer2))
    }

    companion object {
        private const val AUTH_SERVER = "https://example.com:1234/foo/bar"
    }
}
