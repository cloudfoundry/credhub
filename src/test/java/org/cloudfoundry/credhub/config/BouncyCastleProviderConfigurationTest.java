package org.cloudfoundry.credhub.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha256WithRSAEncryption;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes=BouncyCastleProviderConfiguration.class)
public class BouncyCastleProviderConfigurationTest {

  @Autowired
  JcaContentSignerBuilder jcaContentSignerBuilder;

  private KeyPairGenerator generator;

  @Before
  public void beforeEach() throws Exception {
    generator = KeyPairGenerator
        .getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(1024);
  }

  @Test
  public void jcaContentSignerBuilder() throws Exception {
    PrivateKey key = generator.generateKeyPair().getPrivate();

    ContentSigner signer = jcaContentSignerBuilder.build(key);

    assertThat(signer.getAlgorithmIdentifier().getAlgorithm(), equalTo(sha256WithRSAEncryption));
  }
}
