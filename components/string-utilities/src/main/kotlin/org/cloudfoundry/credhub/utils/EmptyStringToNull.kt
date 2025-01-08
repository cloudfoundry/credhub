package org.cloudfoundry.credhub.utils

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import java.io.IOException

class EmptyStringToNull : JsonDeserializer<String>() {
    @Throws(IOException::class)
    override fun deserialize(
        jsonParser: JsonParser,
        context: DeserializationContext,
    ): String? {
        val node = jsonParser.readValueAsTree<JsonNode>()
        if (node.asText().isEmpty()) {
            return null
        } else {
            return node.textValue()
        }
    }
}
