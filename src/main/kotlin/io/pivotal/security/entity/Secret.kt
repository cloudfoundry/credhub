package io.pivotal.security.entity

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty

data class Secret @JsonCreator constructor(
    @JsonProperty("value")
    var value: String,

    @JsonProperty("type")
    var type: String
) {
    init {
        if (!"value".equals(type)) {
            throw Exception("unknown type")
        }
    }
}