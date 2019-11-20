package org.cloudfoundry.credhub.auth

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException

class OAuthSignatureException(msg: String) : ClientAuthenticationException(msg) {

    override fun getHttpErrorCode(): Int {
        return 401
    }

    override fun getOAuth2ErrorCode(): String {
        return "invalid_token"
    }
}
