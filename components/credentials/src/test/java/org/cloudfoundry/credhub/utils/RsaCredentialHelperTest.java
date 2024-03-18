package org.cloudfoundry.credhub.utils;

import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class RsaCredentialHelperTest {
  @Test
  public void getKeyLength_returnsLengthOfPublicKey() {
    final RsaCredentialVersionData rsaCredentialData = new RsaCredentialVersionData("testRsa");
    final String publicKey = "-----BEGIN PUBLIC KEY-----\n"
      + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoRIqdibiYHKZhyH91xYR\n"
      + "Tpz728+A8d/t2U2e8OIhNqI7pjh5uKnbmeoAXdZAbGN3TW7xArdMAUOSRhELH0Gc\n"
      + "8XGz6ZnY+KGuTnmBO+ZamE3kltwqJBfxwV2UGV5bJIVVToLpLa1GDF4p7g8I8W/a\n"
      + "KURKCgMNlRQw38Wi8yuEWyCHWHrqon8CcA5ovUg1pyrpR9i+5NTCRadDf1JIQfKB\n"
      + "Mt/gA/s6+ZaWOB6mbWv67OUS5wHWe0tcX2g4KK3IDlkzKQulSHQoIPEf+7l+vJEJ\n"
      + "KT+C2cI+pl/qLVtbY+jsNr8acxja0ri4pUGEQPKP5009qisloEDlQMb/gMT5aHoF\n"
      + "8GORc1EloUG4CpnPUe0L63Q3uSZkLSPAiYqwCi7Wu/L7aVeynGk3CFIPALyh/hIi\n"
      + "SCOX6Jc81o9hZLADEFx4o4qaK4/MQczLaPkESO2578MI+eNwV3d02CIaUeSzK91b\n"
      + "ZlAsqUUXaxxOQ+0WcJpE1O+IUXoBJ7XSZAqfdogLVUM0A+wW8Duxthuh1j7z284B\n"
      + "NjWi9nPZnD3KT0vLv8KbwrW0XgiMzsaAdZKlexKZQuuzAOVNHb0hd3H36lBqAOPg\n"
      + "G0S+H7L3o8XAPcqkke2xs/tcfF05DX+kpD2xdeDWs9MK39FnGtYp8gTKoDkzf0vp\n"
      + "o2oUFe5cAKZHziOqNuoc7SUCAwEAAQ==\n"
      + "-----END PUBLIC KEY-----";
    rsaCredentialData.setPublicKey(publicKey);
    final RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

    assertThat(rsaHelper.getKeyLength(), equalTo(4096));
  }

  @Test
  public void getKeyLength_whenPublicKeyIsNotSet_returnsZero() {
    final RsaCredentialVersionData rsaCredentialData = new RsaCredentialVersionData("testRsa");
    final RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

    assertThat(rsaHelper.getKeyLength(), equalTo(0));
  }

  @Test
  public void getKeyLength_whenPublicKeyIsInvalid_throwsException() {
    final RsaCredentialVersionData rsaCredentialData = new RsaCredentialVersionData("testRsa");
    final String publicKey = "This is a key that is obviously incorrect. Is it not?";
    rsaCredentialData.setPublicKey(publicKey);
    final RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

    assertThrows(RuntimeException.class, () ->
      rsaHelper.getKeyLength()
    );
  }
}
