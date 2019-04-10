package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant
import java.util.UUID

data class CertificateVersionView(
    val id: UUID,
    @JsonProperty("expiry_date")
    val expiryDate: Instant,
    val transitional: Boolean
)
