package com.margelo.nitro.v1probe;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PBKDF2 for the kernel runtime, called from C++ over JNI on a background thread.
 *
 * `derive` uses SecretKeyFactory with a PBEKeySpec whose chars are decoded from the password's
 * UTF-8 bytes — whether the provider re-encodes chars as UTF-8 or takes the low byte is
 * provider-specific, so correctness is verified by the kernel probe vectors. `deriveMac` is the
 * byte-exact RFC 8018 implementation over javax.crypto.Mac and ships if SecretKeyFactory mismatches.
 */
public final class KernelPbkdf2 {
  private KernelPbkdf2() {}

  public static byte[] derive(String algorithm, byte[] password, byte[] salt, int iterations, int length)
      throws GeneralSecurityException {
    if (salt.length == 0) {
      // PBEKeySpec rejects empty salts; RFC 8018 over Mac handles them fine.
      String hmac = algorithm.endsWith("SHA256") ? "HmacSHA256" : "HmacSHA512";
      return deriveMac(hmac, password, salt, iterations, length);
    }
    char[] chars = new String(password, StandardCharsets.UTF_8).toCharArray();
    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, length * 8);
    Arrays.fill(chars, '\0');
    Arrays.fill(password, (byte) 0);
    try {
      return SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
    } finally {
      spec.clearPassword();
    }
  }

  public static byte[] deriveMac(String hmacAlgorithm, byte[] password, byte[] salt, int iterations, int length)
      throws GeneralSecurityException {
    SecretKeySpec key = new SecretKeySpec(password, hmacAlgorithm);
    Mac mac = Mac.getInstance(hmacAlgorithm);
    mac.init(key);
    int blockSize = mac.getMacLength();
    int blocks = (length + blockSize - 1) / blockSize;
    byte[] out = new byte[blocks * blockSize];
    byte[] index = new byte[4];
    int offset = 0;
    for (int block = 1; block <= blocks; block++) {
      index[0] = (byte) (block >>> 24);
      index[1] = (byte) (block >>> 16);
      index[2] = (byte) (block >>> 8);
      index[3] = (byte) block;
      mac.update(salt);
      byte[] u = mac.doFinal(index);
      byte[] t = u.clone();
      for (int j = 1; j < iterations; j++) {
        u = mac.doFinal(u);
        for (int k = 0; k < u.length; k++) {
          t[k] ^= u[k];
        }
      }
      System.arraycopy(t, 0, out, offset, blockSize);
      offset += blockSize;
      Arrays.fill(u, (byte) 0);
      Arrays.fill(t, (byte) 0);
    }
    Arrays.fill(password, (byte) 0);
    byte[] result = Arrays.copyOf(out, length);
    Arrays.fill(out, (byte) 0);
    return result;
  }
}
