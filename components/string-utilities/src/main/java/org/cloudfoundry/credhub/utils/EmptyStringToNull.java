package org.cloudfoundry.credhub.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

public class EmptyStringToNull extends JsonDeserializer<String> {

  @Override
  public String deserialize(final JsonParser jsonParser, final DeserializationContext context)
    throws IOException {
    final JsonNode node = jsonParser.readValueAsTree();
    if (node.asText().isEmpty()) {
      return null;
    }
    return node.textValue();
  }

}
