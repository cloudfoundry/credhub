package org.cloudfoundry.credhub.auth

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException

class OAuthSignatureException(
    msg: String,
) : ClientAuthenticationException(msg) {
    override fun getHttpErrorCode(): Int = 401

    override fun getOAuth2ErrorCode(): String = "invalid_token"
}
