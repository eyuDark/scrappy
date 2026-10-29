import type { Detector } from "@scrappy/core";
import { emailDetector } from "./email.ts";
import { apiKeyDetector, bearerTokenDetector, jwtDetector, passwordAssignmentDetector, privateKeyDetector, urlCredentialsDetector } from "./secrets.ts";

export { createPatternDetector, type PatternDetectorOptions } from "./pattern.ts";
export { emailDetector, apiKeyDetector, bearerTokenDetector, jwtDetector, passwordAssignmentDetector, privateKeyDetector, urlCredentialsDetector };

export const defaultDetectors: readonly Detector[] = Object.freeze([
  privateKeyDetector,
  jwtDetector,
  apiKeyDetector,
  bearerTokenDetector,
  urlCredentialsDetector,
  passwordAssignmentDetector,
  emailDetector,
]);
