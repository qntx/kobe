# Called from native code over JNI; R8 would otherwise strip or rename it.
-keep class com.margelo.nitro.v1probe.KernelPbkdf2 {
  public static byte[] derive(java.lang.String, byte[], byte[], int, int);
}
