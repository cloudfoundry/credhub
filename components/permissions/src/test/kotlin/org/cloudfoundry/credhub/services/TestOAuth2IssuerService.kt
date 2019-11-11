package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.auth.OAuth2IssuerService
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("unit-test")
class TestOAuth2IssuerService : OAuth2IssuerService {
    override fun getIssuer(): String {
        return "https://example.com:8443/oauth/token"
    }
}
