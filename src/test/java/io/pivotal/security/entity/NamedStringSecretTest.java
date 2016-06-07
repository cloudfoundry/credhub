package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class NamedStringSecretTest {
  @Test
  public void canCreateModelFromEntity() throws Exception {
    NamedStringSecret subject = new NamedStringSecret("Foo");
    subject.setValue("my-value");
    Object actual = subject.convertToModel();
    assertThat(new ObjectMapper().writer().writeValueAsString(actual), equalTo("{\"value\":\"my-value\",\"type\":\"value\"}"));
  }
}