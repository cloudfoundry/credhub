package org.cloudfoundry.credhub.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;

public class EmptyStringToNull extends JsonDeserializer<String> {

  @Override
  public String deserialize(JsonParser jsonParser, DeserializationContext context)
      throws IOException {
    JsonNode node = jsonParser.readValueAsTree();
    if (node.asText().isEmpty()) {
      return null;
    }
    return node.textValue();
  }

}
