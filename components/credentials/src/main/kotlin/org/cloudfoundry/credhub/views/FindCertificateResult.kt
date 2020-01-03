package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

class FindCertificateResult(versionCreatedAt: Instant, name: String, @get:JsonProperty val expiryDate: Instant) : FindCredentialResult(versionCreatedAt, name)
