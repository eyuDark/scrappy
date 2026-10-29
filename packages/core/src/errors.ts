// Messages are fixed strings: errors must never carry input text or mapped values.
const MESSAGES = {
  INVALID_INPUT: "Input must be a string.",
  INPUT_TOO_LARGE: "Input exceeds the maximum allowed length.",
  INVALID_OPTIONS: "Invalid options.",
  DETECTOR_FAILED: "A detector failed; no output was produced.",
  SESSION_DISPOSED: "The session has been disposed.",
  RESTORE_UNAVAILABLE: "Restoration is only available in reversible mode.",
  UNSUPPORTED_VALUE: "Value is not JSON-compatible.",
  CYCLIC_VALUE: "Value contains a circular reference.",
  MAX_DEPTH_EXCEEDED: "Value is nested too deeply.",
} as const;

export type ScrappyErrorCode = keyof typeof MESSAGES;

export class ScrappyError extends Error {
  readonly code: ScrappyErrorCode;

  /** `detail` must be safe to log: an option name, detector id or sanitized JSON path. */
  constructor(code: ScrappyErrorCode, detail?: string) {
    super(detail ? `${MESSAGES[code]} (${detail})` : MESSAGES[code]);
    this.name = "ScrappyError";
    this.code = code;
  }
}
