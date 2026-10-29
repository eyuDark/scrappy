import * as core from "@scrappy/core";
import { defaultDetectors } from "@scrappy/detectors";

export { ScrappyError, DEFAULT_MAX_INPUT_LENGTH, SENSITIVE_TYPES } from "@scrappy/core";
export type * from "@scrappy/core";
export * from "@scrappy/detectors";

/** Same as core options, but `detectors` defaults to `defaultDetectors`. Pass `[...defaultDetectors, mine]` to extend. */
export type SdkOptions = Omit<core.SessionOptions, "detectors"> & { detectors?: readonly core.Detector[] };

const withDefaults = (options: SdkOptions = {}): core.SessionOptions => ({ ...options, detectors: options.detectors ?? defaultDetectors });

export const createSession = (options?: SdkOptions) => core.createSession(withDefaults(options));
export const sanitize = (input: string, options?: SdkOptions) => core.sanitize(input, withDefaults(options));
export const sanitizeJson = (value: unknown, options?: SdkOptions) => core.sanitizeJson(value, withDefaults(options));
