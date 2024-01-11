package org.cloudfoundry.credhub.auth

import org.cloudfoundry.credhub.RestTemplateFactory
import org.cloudfoundry.credhub.config.OAuthProperties
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.util.HashMap

@Service
@ConditionalOnProperty("security.oauth2.enabled")
@Profile("prod", "dev", "!unit-test")
class DefaultOAuth2IssuerService @Autowired
@Throws(URISyntaxException::class, CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, KeyManagementException::class, IOException::class)
internal constructor(
    restTemplateFactory: RestTemplateFactory,
    oAuthProperties: OAuthProperties
) : OAuth2IssuerService {

    private val authServerUri: URI = oAuthProperties.issuerPath
    private val restTemplate: RestTemplate = restTemplateFactory
        .createRestTemplate(oAuthProperties.trustStore!!, oAuthProperties.trustStorePassword!!)

    private var issuer: String? = null

    override fun getIssuer(): String? {
        return if (issuer != null) issuer else fetchIssuer()
    }

    fun fetchIssuer(): String? {
        issuer = restTemplate
            .getForEntity(
                authServerUri,
                HashMap::class.java
            )
            .body!!["issuer"] as String

        return issuer
    }
}
