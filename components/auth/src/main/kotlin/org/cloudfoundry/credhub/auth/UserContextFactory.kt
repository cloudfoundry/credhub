package org.cloudfoundry.credhub.auth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component
import java.security.cert.X509Certificate

@Component
class UserContextFactory {
    @Autowired(required = false)
//    private val resourceServerTokenServices: ResourceServerTokenServices? = null
    /*
     * The "iat" and "exp" claims are parsed by Jackson as integers,
     * because JWT defines these as seconds since Epoch
     * (https://tools.ietf.org/html/rfc7519#section-2). That means it has a
     * Year-2038 bug. To adapt to our local model, hoping JWT will some day be improved,
     * this function returns a numeric value as long.
     */
    private fun claimValueAsLong(additionalInformation: Map<String, Any>): Long =
        (additionalInformation["iat"] as Number).toLong()

    fun createUserContext(authentication: Authentication?): UserContext =
        if (authentication is PreAuthenticatedAuthenticationToken) {
            createUserContext(authentication)
        } else {
            createUserContext(authentication as JwtAuthenticationToken, null)
        }

    fun createUserContext(
        authentication: JwtAuthenticationToken,
        maybeToken: String?,
    ): UserContext {
        val jwt: Jwt = authentication.principal as Jwt
        val claims = jwt.claims
        val grantType = claims["grant_type"] as String
        val clientId = claims["client_id"] as String
        val userId = claims["user_id"] as String?
        val userName = claims["user_name"] as String?
        val issuer = claims["iss"] as String?
        val validFrom: Long = 0
        val validUntil: Long = 0
        val scopes = claims["scope"] as List<*>
        val scope = scopes.joinToString(",")

        // TODO: Will other tests fail without the below?
//        var token = maybeToken
//
//        if (maybeToken == null) {
//            val authDetails =
//                authentication
//                    .details as OAuth2AuthenticationDetails
//            token = authDetails.tokenValue
//        }

//        val accessToken: OAuth2AccessToken?
//        accessToken = resourceServerTokenServices!!.readAccessToken(token)
//
//        if (accessToken != null) {
//            val scopes = accessToken.scope
//            scope = scopes.joinToString(",")
//
//            val additionalInformation = accessToken.additionalInformation
//            userName = additionalInformation["user_name"] as String?
//            userId = additionalInformation["user_id"] as String?
//            issuer = additionalInformation["iss"] as String?
//            validFrom = claimValueAsLong(additionalInformation)
//            validUntil = accessToken.expiration.toInstant().epochSecond
//        }

        return UserContext(
            userId,
            userName,
            issuer,
            validFrom,
            validUntil,
            clientId,
            scope,
            grantType,
            UserContext.AUTH_METHOD_UAA,
        )
    }

    private fun createUserContext(authentication: PreAuthenticatedAuthenticationToken): UserContext {
        val certificate = authentication.credentials as X509Certificate

        return UserContext(
            certificate.notBefore.toInstant().epochSecond,
            certificate.notAfter.toInstant().epochSecond,
            certificate.subjectDN.name,
            UserContext.AUTH_METHOD_MUTUAL_TLS,
        )
    }
}
