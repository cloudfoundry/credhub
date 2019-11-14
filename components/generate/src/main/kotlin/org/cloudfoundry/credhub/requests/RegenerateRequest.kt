package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import javax.validation.constraints.NotNull
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages

@JsonAutoDetect
class RegenerateRequest {

    @NotNull(message = ErrorMessages.MISSING_NAME)
    private lateinit var name: String

    constructor() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(name: String) {
        this.name = name
    }

    fun getName(): String {
        return name
    }

    fun setName(name: String) {
        this.name = StringUtils.prependIfMissing(name, "/")
    }
}
