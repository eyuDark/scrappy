import type { Detector } from "@scrappy/core";
import { emailDetector } from "./email.ts";
import { ipAddressDetector, paymentCardDetector, phoneDetector } from "./pii.ts";
import { apiKeyDetector, bearerTokenDetector, jwtDetector, passwordAssignmentDetector, privateKeyDetector, unknownTokenDetector, urlCredentialsDetector } from "./secrets.ts";

export { createPatternDetector, type PatternDetectorOptions } from "./pattern.ts";
export { emailDetector, ipAddressDetector, paymentCardDetector, phoneDetector, apiKeyDetector, bearerTokenDetector, jwtDetector, passwordAssignmentDetector, privateKeyDetector, unknownTokenDetector, urlCredentialsDetector };

export const defaultDetectors: readonly Detector[] = Object.freeze([
  privateKeyDetector,
  jwtDetector,
  apiKeyDetector,
  bearerTokenDetector,
  urlCredentialsDetector,
  passwordAssignmentDetector,
  emailDetector,
  paymentCardDetector,
  phoneDetector,
  unknownTokenDetector,
]);
