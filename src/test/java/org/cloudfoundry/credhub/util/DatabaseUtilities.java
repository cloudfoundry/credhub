package org.cloudfoundry.credhub.util;

public final class DatabaseUtilities {
  private DatabaseUtilities() {
  }

  public static byte[] getExceedsMaxBlobStoreSizeBytes() {
    int exceedsMaxBlobStoreSize = 70000;
    byte[] exceedsMaxBlobStoreValue = new byte[exceedsMaxBlobStoreSize];
    for (int i = 0; i < exceedsMaxBlobStoreSize; i++) {
      byte randomNumber = (byte) Math.round(Math.random() * 10);
      exceedsMaxBlobStoreValue[i] = randomNumber;
    }

    return exceedsMaxBlobStoreValue;
  }
}
