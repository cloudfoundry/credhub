package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.cloudfoundry.credhub.utils.TestPasswordKeyProxyFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;
import static org.cloudfoundry.credhub.constants.EncryptionConstants.NONCE_SIZE;
import static org.cloudfoundry.credhub.constants.EncryptionConstants.SALT_SIZE;
import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PasswordBasedKeyProxyTest {
  private PasswordBasedKeyProxy subject;
  private String password;

  private PasswordEncryptionService encryptionService;

  @Before
  public void beforeEach() throws Exception {
    password = "abcdefghijklmnopqrst";
    encryptionService = new PasswordEncryptionService(new TestPasswordKeyProxyFactory());
    subject = new PasswordBasedKeyProxy(password, 1, encryptionService);
  }

  @Test
  public void deriveKey_returnstheExpectedKey() {
    final String knownRandomNumber = "7034522dc85138530e44b38d0569ca67";
    final String knownGeneratedKey = "09cafa70264eaa47dcf0678dfd03aa73d24044df47b0381c17ebe0ed4e2f3d91";

    final byte[] salt = Hex.decode(knownRandomNumber); // gen'dp originally from SecureRandom..

    final Key derivedKey = subject.deriveKey(Collections.unmodifiableList(asList(ArrayUtils.toObject(salt))));

    final String hexOutput = Hex.toHexString(derivedKey.getEncoded());

    assertThat(hexOutput, equalTo(knownGeneratedKey));
    assertThat(derivedKey.getEncoded().length, equalTo(32));
  }

  @Test
  public void matchesCanary_whenCanaryMatches_setsTheKey() throws Exception {
    // Generate a key from the password and a new salt
    final PasswordBasedKeyProxy oldProxy = new PasswordBasedKeyProxy(password, 1, encryptionService);
    final Key derivedKey = oldProxy.deriveKey();
    final List<Byte> salt = oldProxy.getSalt();

    // Create a canary whose value is encrypted with this key
    final EncryptedValue encryptedCanaryValue = encryptionService.encrypt(null, derivedKey, CANARY_VALUE);
    final EncryptionKeyCanary canary = new EncryptionKeyCanary();
    canary.setEncryptedCanaryValue(encryptedCanaryValue.getEncryptedValue());
    canary.setNonce(encryptedCanaryValue.getNonce());
    final Byte[] saltArray = new Byte[salt.size()];
    canary.setSalt(toPrimitive(salt.toArray(saltArray)));

    final boolean match = subject.matchesCanary(canary);
    assertTrue(match);
    assertThat(subject.getKey(), equalTo(derivedKey));
  }

  @Test
  public void matchesCanary_whenCanaryDoesNotMatch_doesNotAffectTheKey() throws Exception {
    // Create a canary whose value cannot be decrypted by any key
    final EncryptionKeyCanary canary = new EncryptionKeyCanary();
    canary.setSalt(new byte[SALT_SIZE]);
    canary.setNonce(new byte[NONCE_SIZE]);
    canary.setEncryptedCanaryValue(new byte[32]);

    // Set some well-known but bogus key into the subject
    final Key bogusKey = mock(Key.class);
    subject.setKey(bogusKey);
    final boolean match = subject.matchesCanary(canary);

    assertFalse(match);
    assertThat(subject.getKey(), equalTo(bogusKey));
  }

  @Test
  public void matchesCanary_whenCanaryDoesNotContainSalt_returnsFalse() {
    final EncryptionKeyCanary canary = new EncryptionKeyCanary();
    canary.setSalt(null);
    assertFalse(subject.matchesCanary(canary));
  }

  @Test
  public void matchesCanary_whenCanaryHasEmptySalt_returnsFalse() {
    final EncryptionKeyCanary canary = new EncryptionKeyCanary();
    canary.setSalt("".getBytes(StringUtil.UTF_8));
    assertFalse(subject.matchesCanary(canary));
  }

  @Test
  public void getKey_whenNoKeyHasBeenSet_derivesNewKeyAndSalt() {
    subject = new PasswordBasedKeyProxy("some password", 1, encryptionService);
    assertThat(subject.getSalt(), equalTo(null));

    assertThat(subject.getKey(), not(equalTo(null)));
    assertThat(subject.getSalt(), not(equalTo(null)));
  }

  @Test
  public void generateSalt_returnsSaltOfAtLeastSizeOfHashFunctionOutput() {
    subject = new PasswordBasedKeyProxy("some password", 1, encryptionService);
    assertThat(subject.generateSalt().size(), greaterThanOrEqualTo(48));
  }

  @Test
  public void generateSalt_usesCorrectSecureRandom() {
    final InternalEncryptionService mockEncryptionService = mock(InternalEncryptionService.class);
    when(mockEncryptionService.getSecureRandom()).thenReturn(new SecureRandom());

    subject = new PasswordBasedKeyProxy("some password", 1, mockEncryptionService);
    subject.generateSalt();

    verify(mockEncryptionService).getSecureRandom();
  }
}
