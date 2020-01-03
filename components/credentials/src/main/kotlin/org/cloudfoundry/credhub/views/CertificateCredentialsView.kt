package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty

class CertificateCredentialsView(@get:JsonProperty val certificates: List<CertificateCredentialView>)
