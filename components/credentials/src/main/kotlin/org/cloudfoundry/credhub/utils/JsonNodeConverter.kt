package org.cloudfoundry.credhub.utils

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.persistence.AttributeConverter

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
