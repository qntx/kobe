package com.margelo.nitro.v1probe;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * PBKDF2 for the kernel runtime, called from C++ over JNI on the dedicated KDF worker thread.
 *
 * Byte-exact RFC 8018 derivation over javax.crypto.Mac — there is no SecretKeyFactory/PBEKeySpec
 * path, because chars decoded from the password's UTF-8 bytes are provider-specific. All
 * intermediate arrays the VM hands back (u, t, out) are wiped. Note that SecretKeySpec and JCA
 * provider internals retain their own non-wipeable copies of the key material; the caller-side
 * buffers are still zeroed by JniByteArray after return.
 */
public final class KernelPbkdf2 {
  private KernelPbkdf2() {}

  public static byte[] derive(String hmacAlgorithm, byte[] password, byte[] salt, int iterations, int length)
      throws GeneralSecurityException {
    SecretKeySpec key = new SecretKeySpec(password, hmacAlgorithm);
    Mac mac = Mac.getInstance(hmacAlgorithm);
    mac.init(key);
    int blockSize = mac.getMacLength();
    int blocks = (length + blockSize - 1) / blockSize;
    byte[] out = new byte[blocks * blockSize];
    byte[] index = new byte[4];
    int offset = 0;
    try {
      for (int block = 1; block <= blocks; block++) {
        index[0] = (byte) (block >>> 24);
        index[1] = (byte) (block >>> 16);
        index[2] = (byte) (block >>> 8);
        index[3] = (byte) block;
        mac.update(salt);
        byte[] u = mac.doFinal(index);
        byte[] t = u.clone();
        for (int j = 1; j < iterations; j++) {
          byte[] next = mac.doFinal(u);
          Arrays.fill(u, (byte) 0);
          u = next;
          for (int k = 0; k < u.length; k++) {
            t[k] ^= u[k];
          }
        }
        System.arraycopy(t, 0, out, offset, blockSize);
        offset += blockSize;
        Arrays.fill(u, (byte) 0);
        Arrays.fill(t, (byte) 0);
      }
      return Arrays.copyOf(out, length);
    } finally {
      Arrays.fill(out, (byte) 0);
      Arrays.fill(index, (byte) 0);
      Arrays.fill(password, (byte) 0);
    }
  }
}
