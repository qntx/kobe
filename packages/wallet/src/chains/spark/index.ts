/**
 * Spark public surface (`wallet/spark`).
 */
export {
  encodeSparkAddress,
  SPARK_PURPOSE,
  sparkHrp,
  sparkPath,
  type SparkNetwork,
} from "./address.ts";
export { createSparkDeriver, type SparkDeriver } from "./deriver.ts";
export {
  createSparkSigner,
  SparkSigner,
  sparkMessageDigest,
  sparkSignerFromBytes,
  sparkSignerFromDerived,
  sparkSignerFromHex,
  sparkSignerFromSecretKey,
} from "./signer.ts";
export type { SparkSigner as SparkSignerApi } from "./signer.ts";
