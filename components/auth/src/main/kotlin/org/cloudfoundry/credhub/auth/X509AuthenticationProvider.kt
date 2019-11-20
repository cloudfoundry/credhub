package org.cloudfoundry.credhub.auth

import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component

@Component
class X509AuthenticationProvider : PreAuthenticatedAuthenticationProvider() {
    init {
        setPreAuthenticatedUserDetailsService(x509v3ExtService())
    }

    private fun x509v3ExtService(): AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
        return AuthenticationUserDetailsService { token -> User(token.name, "", AuthorityUtils.createAuthorityList(ROLE_MTLS_USER)) }
    }

    override fun authenticate(authentication: Authentication): Authentication? {
        val result = super.authenticate(authentication)

        if (result != null && authentication.credentials is X509Certificate) {
            val certificate = authentication.credentials as X509Certificate

            /*
        The following exceptions are wrapped in
        InternalAuthenticationServiceException to avoid the logic in
        org.springframework.security.authentication.ProviderManager
        from allowing another provider an
        attempt after this failure.
       */

            try {
                val extKeyUsage = certificate.extendedKeyUsage
                if (extKeyUsage == null || !extKeyUsage.contains(CLIENT_AUTH_EXTENDED_KEY_USAGE)) {
                    val throwable = BadCredentialsException("")

                    throw InternalAuthenticationServiceException("Certificate does not contain: $CLIENT_AUTH_EXTENDED_KEY_USAGE", throwable)
                }
            } catch (e: CertificateParsingException) {
                val throwable = BadCredentialsException("")

                throw InternalAuthenticationServiceException("Certificate Extended Key Usage unreadable", throwable)
            }
        }
        return result
    }

    companion object {

        val CLIENT_AUTH_EXTENDED_KEY_USAGE = KeyPurposeId.id_kp_clientAuth.id
        // Spring's access assertion language's hasRole() takes
        // {@link ROLE_MTLS_USER} without "ROLE_" prefix
        val MTLS_USER = "MTLS_USER"
        private val ROLE_MTLS_USER = "ROLE_MTLS_USER"
    }
}
