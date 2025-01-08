package org.cloudfoundry.credhub.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.net.URI
import java.net.URISyntaxException

@Configuration
@ConfigurationProperties("auth-server")
@ConditionalOnProperty("security.oauth2.enabled")
class OAuthProperties {
    @Value("\${internal_url:#{null}}")
    private var internalUrl: String? = null
    var url: String? = null
    var trustStore: String? = null
    var trustStorePassword: String? = null

    val issuerPath: URI
        @Throws(URISyntaxException::class)
        get() = getResolvedUri(ISSUER_PATH)

    val jwkKeysPath: String
        @Throws(URISyntaxException::class)
        get() = getResolvedUri(JWK_KEYS_PATH).toString()

    fun setInternalUrl(internalUrl: String) {
        this.internalUrl = internalUrl
    }

    @Throws(URISyntaxException::class)
    private fun getResolvedUri(extension: String): URI {
        val authServer = if (internalUrl != null) internalUrl else url
        val base = URI(authServer!!)
        val path = base.path.plus(extension)
        return base.resolve(path)
    }

    companion object {
        private val ISSUER_PATH = "/.well-known/openid-configuration"
        private val JWK_KEYS_PATH = "/token_keys"
    }
}
