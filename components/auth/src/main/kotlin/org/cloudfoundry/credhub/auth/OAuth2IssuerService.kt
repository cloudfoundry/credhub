package org.cloudfoundry.credhub.auth

interface OAuth2IssuerService {
    fun getIssuer(): String?
}
