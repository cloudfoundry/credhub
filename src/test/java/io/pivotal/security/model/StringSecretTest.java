package io.pivotal.security.model;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import org.springframework.util.Assert;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
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