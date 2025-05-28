package org.cloudfoundry.credhub.auth

import org.apache.logging.log4j.LogManager
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component
import java.security.cert.X509Certificate
import java.time.Instant

@Component
class UserContextFactory {
    @Autowired(required = false)
    fun createUserContext(authentication: Authentication?): UserContext =
        if (authentication == null) {
            LOGGER.trace("authentication is null")
            UserContext()
        } else if (authentication is PreAuthenticatedAuthenticationToken) {
            LOGGER.trace("authentication is PreAuthenticatedAuthenticationToken")
            createUserContext(authentication as PreAuthenticatedAuthenticationToken)
        } else {
            LOGGER.trace("authentication is JwtAuthenticationToken")
            createUserContext(authentication as JwtAuthenticationToken)
        }

    private fun createUserContext(authentication: JwtAuthenticationToken): UserContext {
        val jwt: Jwt = authentication.principal as Jwt
        val claims = jwt.claims
        val grantType = claims["grant_type"] as String
        val clientId = claims["client_id"] as String
        val userId = claims["user_id"] as String?
        val userName = claims["user_name"] as String?
        val issuer = claims["iss"] as String?
        val validFrom: Long = (claims["iat"] as Instant).epochSecond
        val validUntil: Long = (claims["exp"] as Instant).epochSecond
        val scopes = claims["scope"] as List<*>
        val scope = scopes.joinToString(",")

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
            certificate.subjectX500Principal.name,
            UserContext.AUTH_METHOD_MUTUAL_TLS,
        )
    }

    companion object {
        private val LOGGER = LogManager.getLogger(UserContextFactory::class.java)
    }
}
