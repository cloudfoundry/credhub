package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.databind.JsonNode
import org.cloudfoundry.credhub.ErrorMessages
import javax.validation.constraints.NotNull

@JsonAutoDetect
class RegenerateRequest {
    @NotNull(message = ErrorMessages.MISSING_NAME)
    private lateinit var name: String

    private var metadata: JsonNode? = null

    constructor() {
        // this needs to be there for jackson to be happy
    }

    fun getName(): String = name

    fun getMetadata(): JsonNode? = metadata
}
