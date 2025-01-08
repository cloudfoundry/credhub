package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonAutoDetect

@JsonAutoDetect
class ResponseError(
    val error: String,
)
