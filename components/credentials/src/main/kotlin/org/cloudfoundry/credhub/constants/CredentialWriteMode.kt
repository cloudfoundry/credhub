package org.cloudfoundry.credhub.constants

import com.fasterxml.jackson.annotation.JsonValue

enum class CredentialWriteMode private constructor(
    val mode: String,
) {
    OVERWRITE("overwrite"),
    NO_OVERWRITE("no-overwrite"),
    CONVERGE("converge"),
    ;

    @JsonValue
    fun forJackson(): String = mode

    override fun toString(): String = mode
}
