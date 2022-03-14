package org.cloudfoundry.credhub.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Paths

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
        val path = concatPath(base.path, extension).toString()
        return base.resolve(path)
    }

    private fun concatPath(p1: String, p2: String): String {
        val subPath = if (p2.startsWith("/")) p2.substring(1) else p2
        val path = (if (p1.endsWith("/")) p1 else p1 + "/") + subPath
        return path
    }

    companion object {
        private val ISSUER_PATH = "/.well-known/openid-configuration"
        private val JWK_KEYS_PATH = "/token_keys"
    }
}
