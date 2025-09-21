/**
 * Centralized error handling and logging system
 */

export enum ErrorCode {
  // Authentication errors
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  INVALID_ADDRESS = "INVALID_ADDRESS",
  INVALID_MESSAGE_FORMAT = "INVALID_MESSAGE_FORMAT",
  MESSAGE_PARSE_ERROR = "MESSAGE_PARSE_ERROR",
  NONCE_MISMATCH = "NONCE_MISMATCH",
  MESSAGE_EXPIRED = "MESSAGE_EXPIRED",
  FUTURE_ISSUED_TIME = "FUTURE_ISSUED_TIME",
  MESSAGE_NOT_VALID_YET = "MESSAGE_NOT_VALID_YET",
  INVALID_ADDRESS_FORMAT = "INVALID_ADDRESS_FORMAT",
  UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM",
  CRYPTO_ERROR = "CRYPTO_ERROR",

  // Session errors
  CHALLENGE_NOT_FOUND = "CHALLENGE_NOT_FOUND",
  CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED",
  CHALLENGE_USED = "CHALLENGE_USED",
  SESSION_NOT_FOUND = "SESSION_NOT_FOUND",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  INVALID_TOKEN = "INVALID_TOKEN",

  // Validation errors
  VALIDATION_ERROR = "VALIDATION_ERROR",
  INVALID_INPUT = "INVALID_INPUT",
  MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD",
  INVALID_FORMAT = "INVALID_FORMAT",

  // Rate limiting errors
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",

  // Configuration errors
  CONFIG_ERROR = "CONFIG_ERROR",
  MISSING_CONFIG = "MISSING_CONFIG",

  // Network errors
  NETWORK_ERROR = "NETWORK_ERROR",
  TIMEOUT_ERROR = "TIMEOUT_ERROR",

  // Internal errors
  INTERNAL_ERROR = "INTERNAL_ERROR",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}

export enum ErrorSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export interface AuthError extends Error {
  code: ErrorCode;
  severity: ErrorSeverity;
  details?: Record<string, any>;
  timestamp: number;
  context?: string;
}

export class AuthErrorBuilder {
  private error: Partial<AuthError>;

  constructor(code: ErrorCode, message: string) {
    this.error = {
      name: "AuthError",
      code,
      message,
      severity: this.getSeverityFromCode(code),
      timestamp: Date.now(),
    };
  }

  withDetails(details: Record<string, any>): this {
    this.error.details = details;
    return this;
  }

  withContext(context: string): this {
    this.error.context = context;
    return this;
  }

  withSeverity(severity: ErrorSeverity): this {
    this.error.severity = severity;
    return this;
  }

  build(): AuthError {
    return this.error as AuthError;
  }

  private getSeverityFromCode(code: ErrorCode): ErrorSeverity {
    const severityMap: Record<ErrorCode, ErrorSeverity> = {
      // Critical security issues
      [ErrorCode.INVALID_SIGNATURE]: ErrorSeverity.CRITICAL,
      [ErrorCode.INVALID_ADDRESS]: ErrorSeverity.HIGH,
      [ErrorCode.CRYPTO_ERROR]: ErrorSeverity.CRITICAL,
      [ErrorCode.UNSUPPORTED_ALGORITHM]: ErrorSeverity.HIGH,

      // High security issues
      [ErrorCode.NONCE_MISMATCH]: ErrorSeverity.HIGH,
      [ErrorCode.MESSAGE_EXPIRED]: ErrorSeverity.HIGH,
      [ErrorCode.CHALLENGE_EXPIRED]: ErrorSeverity.HIGH,
      [ErrorCode.CHALLENGE_USED]: ErrorSeverity.HIGH,
      [ErrorCode.SESSION_EXPIRED]: ErrorSeverity.HIGH,

      // Medium issues
      [ErrorCode.INVALID_MESSAGE_FORMAT]: ErrorSeverity.MEDIUM,
      [ErrorCode.MESSAGE_PARSE_ERROR]: ErrorSeverity.MEDIUM,
      [ErrorCode.VALIDATION_ERROR]: ErrorSeverity.MEDIUM,
      [ErrorCode.RATE_LIMIT_EXCEEDED]: ErrorSeverity.MEDIUM,

      // Low issues
      [ErrorCode.CHALLENGE_NOT_FOUND]: ErrorSeverity.LOW,
      [ErrorCode.SESSION_NOT_FOUND]: ErrorSeverity.LOW,
      [ErrorCode.INVALID_INPUT]: ErrorSeverity.LOW,
      [ErrorCode.MISSING_REQUIRED_FIELD]: ErrorSeverity.LOW,
      [ErrorCode.INVALID_FORMAT]: ErrorSeverity.LOW,
      [ErrorCode.CONFIG_ERROR]: ErrorSeverity.LOW,
      [ErrorCode.MISSING_CONFIG]: ErrorSeverity.LOW,
      [ErrorCode.NETWORK_ERROR]: ErrorSeverity.LOW,
      [ErrorCode.TIMEOUT_ERROR]: ErrorSeverity.LOW,
      [ErrorCode.INTERNAL_ERROR]: ErrorSeverity.MEDIUM,
      [ErrorCode.UNKNOWN_ERROR]: ErrorSeverity.MEDIUM,
      [ErrorCode.FUTURE_ISSUED_TIME]: ErrorSeverity.MEDIUM,
      [ErrorCode.MESSAGE_NOT_VALID_YET]: ErrorSeverity.MEDIUM,
      [ErrorCode.INVALID_ADDRESS_FORMAT]: ErrorSeverity.MEDIUM,
      [ErrorCode.INVALID_TOKEN]: ErrorSeverity.MEDIUM,
    };

    return severityMap[code] || ErrorSeverity.MEDIUM;
  }
}

export function createAuthError(
  code: ErrorCode,
  message: string,
  options?: {
    details?: Record<string, any>;
    context?: string;
    severity?: ErrorSeverity;
  }
): AuthError {
  const builder = new AuthErrorBuilder(code, message);
  
  if (options?.details) {
    builder.withDetails(options.details);
  }
  
  if (options?.context) {
    builder.withContext(options.context);
  }
  
  if (options?.severity) {
    builder.withSeverity(options.severity);
  }

  return builder.build();
}

export function isAuthError(error: unknown): error is AuthError {
  return (
    error instanceof Error &&
    "code" in error &&
    "severity" in error &&
    "timestamp" in error
  );
}

export function logError(error: AuthError, logger?: (message: string, meta?: any) => void): void {
  const logMessage = `[${error.severity.toUpperCase()}] ${error.code}: ${error.message}`;
  const meta = {
    code: error.code,
    severity: error.severity,
    timestamp: error.timestamp,
    context: error.context,
    details: error.details,
    stack: error.stack,
  };

  if (logger) {
    logger(logMessage, meta);
  } else {
    // Default logging based on severity
    switch (error.severity) {
      case ErrorSeverity.CRITICAL:
      case ErrorSeverity.HIGH:
        console.error(logMessage, meta);
        break;
      case ErrorSeverity.MEDIUM:
        console.warn(logMessage, meta);
        break;
      case ErrorSeverity.LOW:
        console.info(logMessage, meta);
        break;
    }
  }
}

export function handleError(error: unknown, context?: string): AuthError {
  if (isAuthError(error)) {
    if (context) {
      error.context = context;
    }
    return error;
  }

  // Convert unknown errors to AuthError
  const authError = createAuthError(
    ErrorCode.UNKNOWN_ERROR,
    error instanceof Error ? error.message : "Unknown error occurred",
    {
      context,
      details: {
        originalError: error,
        type: typeof error,
      },
    }
  );

  return authError;
}

export function sanitizeErrorForClient(error: AuthError): {
  code: string;
  message: string;
  timestamp: number;
} {
  // Only expose safe information to clients
  return {
    code: error.code,
    message: error.message,
    timestamp: error.timestamp,
  };
}
