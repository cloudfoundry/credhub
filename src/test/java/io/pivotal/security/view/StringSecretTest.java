package io.pivotal.security.view;

import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.view.StringSecret;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

public class StringSecretTest {

  private StringSecret model;

  @Before
  public void setUp() throws Exception {
    model = new StringSecret("myFavoriteValue");
  }

  @Test
  public void populateEntityEnsuresModelValuesAreInEntity() throws Exception {
    NamedStringSecret entity = new NamedStringSecret();
    model.populateEntity(entity);
    assertThat(entity.getValue(), equalTo("myFavoriteValue"));
  }

}