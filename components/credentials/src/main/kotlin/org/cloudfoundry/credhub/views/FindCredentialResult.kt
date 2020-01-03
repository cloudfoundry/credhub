package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

open class FindCredentialResult(@get:JsonProperty val versionCreatedAt: Instant, @get:JsonProperty("name") val name: String)
