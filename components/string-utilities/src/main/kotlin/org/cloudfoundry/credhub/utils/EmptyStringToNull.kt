package org.cloudfoundry.credhub.utils

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ValueDeserializer
import java.io.IOException

class EmptyStringToNull : ValueDeserializer<String>() {
    @Throws(IOException::class)
    override fun deserialize(
        jsonParser: JsonParser,
        context: DeserializationContext,
    ): String? {
        val node = jsonParser.readValueAsTree<JsonNode>()
        if (node.asString().isEmpty()) {
            return null
        } else {
            return node.stringValue()
        }
    }
}
