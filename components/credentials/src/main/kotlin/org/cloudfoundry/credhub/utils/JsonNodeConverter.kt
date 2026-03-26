package org.cloudfoundry.credhub.utils

import jakarta.persistence.AttributeConverter
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper

class JsonNodeConverter : AttributeConverter<JsonNode, String> {
    override fun convertToDatabaseColumn(attribute: JsonNode?): String = attribute.toString()

    override fun convertToEntityAttribute(dbData: String?): JsonNode {
        val objectMapper = ObjectMapper()

        if (dbData == null) {
            return objectMapper.readTree("")
        }

        return objectMapper.readTree(dbData)
    }
}
