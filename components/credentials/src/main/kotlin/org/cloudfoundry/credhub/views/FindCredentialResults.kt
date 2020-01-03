package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty

class FindCredentialResults(@get:JsonProperty val credentials: List<FindCredentialResult>)
