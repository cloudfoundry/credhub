package org.cloudfoundry.credhub.util;

public final class DatabaseUtilities {
  private DatabaseUtilities() {
    super();
  }

  public static byte[] getExceedsMaxBlobStoreSizeBytes() {
    final int exceedsMaxBlobStoreSize = 70000;
    final byte[] exceedsMaxBlobStoreValue = new byte[exceedsMaxBlobStoreSize];
    for (int i = 0; i < exceedsMaxBlobStoreSize; i++) {
      final byte randomNumber = (byte) Math.round(Math.random() * 10);
      exceedsMaxBlobStoreValue[i] = randomNumber;
    }

    return exceedsMaxBlobStoreValue;
  }
}
