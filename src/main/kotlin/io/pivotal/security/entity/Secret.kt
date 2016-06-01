package io.pivotal.security.entity

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import javax.validation.constraints.Pattern

data class Secret @JsonCreator constructor(
    @JsonProperty("value")
    var value: String,

    @JsonProperty("type")
    @field:Pattern(regexp = "value")
    var type: String
)