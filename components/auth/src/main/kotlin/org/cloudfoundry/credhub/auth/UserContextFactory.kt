package org.cloudfoundry.credhub.auth

import java.security.cert.X509Certificate
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component

@Component
class UserContextFactory {
    @Autowired(required = false)
    private val resourceServerTokenServices: ResourceServerTokenServices? = null

    /*
   * The "iat" and "exp" claims are parsed by Jackson as integers,
   * because JWT defines these as seconds since Epoch
   * (https://tools.ietf.org/html/rfc7519#section-2). That means it has a
   * Year-2038 bug. To adapt to our local model, hoping JWT will some day be improved,
   * this function returns a numeric value as long.
   */
    private fun claimValueAsLong(additionalInformation: Map<String, Any>): Long {
        return (additionalInformation["iat"] as Number).toLong()
    }

    fun createUserContext(authentication: Authentication?): UserContext {
        return if (authentication is PreAuthenticatedAuthenticationToken) {
            createUserContext(authentication)
        } else {
            createUserContext(authentication as OAuth2Authentication, null)
        }
    }

    fun createUserContext(authentication: OAuth2Authentication, maybeToken: String?): UserContext {
        val oauth2Request = authentication.oAuth2Request
        val clientId = oauth2Request.clientId
        val grantType = oauth2Request.grantType
        var userId: String? = null
        var userName: String? = null
        var issuer: String? = null
        var validFrom: Long = 0
        var validUntil: Long = 0
        lateinit var scope: String

        var token = maybeToken

        if (maybeToken == null) {
            val authDetails = authentication
                .details as OAuth2AuthenticationDetails
            token = authDetails.tokenValue
        }

        val accessToken: OAuth2AccessToken?
        accessToken = resourceServerTokenServices!!.readAccessToken(token)

        if (accessToken != null) {
            val scopes = accessToken.scope
            scope = scopes.joinToString(",")

            val additionalInformation = accessToken.additionalInformation
            userName = additionalInformation["user_name"] as String?
            userId = additionalInformation["user_id"] as String?
            issuer = additionalInformation["iss"] as String?
            validFrom = claimValueAsLong(additionalInformation)
            validUntil = accessToken.expiration.toInstant().epochSecond
        }

        return UserContext(
            userId,
            userName,
            issuer,
            validFrom,
            validUntil,
            clientId,
            scope,
            grantType,
            UserContext.AUTH_METHOD_UAA
        )
    }

    private fun createUserContext(authentication: PreAuthenticatedAuthenticationToken): UserContext {
        val certificate = authentication.credentials as X509Certificate

        return UserContext(
            certificate.notBefore.toInstant().epochSecond,
            certificate.notAfter.toInstant().epochSecond,
            certificate.subjectDN.name,
            UserContext.AUTH_METHOD_MUTUAL_TLS
        )
    }
}
