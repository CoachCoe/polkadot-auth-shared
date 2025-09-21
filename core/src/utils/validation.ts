/**
 * Input validation utilities for security
 */

export interface ValidationResult {
  isValid: boolean;
  error?: string;
  sanitized?: string;
}

/**
 * Validate and sanitize string input
 */
export function validateString(
  input: unknown,
  options: {
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
    required?: boolean;
    allowEmpty?: boolean;
  } = {}
): ValidationResult {
  const {
    minLength = 0,
    maxLength = 1000,
    pattern,
    required = false,
    allowEmpty = false,
  } = options;

  // Check if input is a string
  if (typeof input !== "string") {
    return {
      isValid: false,
      error: "Input must be a string",
    };
  }

  // Check if required but empty
  if (required && !input.trim()) {
    return {
      isValid: false,
      error: "Input is required",
    };
  }

  // Check if empty is not allowed
  if (!allowEmpty && !input.trim()) {
    return {
      isValid: false,
      error: "Input cannot be empty",
    };
  }

  // Sanitize input (remove potentially dangerous characters)
  const sanitized = input
    .trim()
    .replace(/[<>\"'&]/g, "") // Remove HTML/XML special characters
    .replace(/[\x00-\x1F\x7F]/g, ""); // Remove control characters

  // Check length constraints
  if (sanitized.length < minLength) {
    return {
      isValid: false,
      error: `Input must be at least ${minLength} characters long`,
    };
  }

  if (sanitized.length > maxLength) {
    return {
      isValid: false,
      error: `Input must be no more than ${maxLength} characters long`,
    };
  }

  // Check pattern if provided
  if (pattern && !pattern.test(sanitized)) {
    return {
      isValid: false,
      error: "Input does not match required pattern",
    };
  }

  return {
    isValid: true,
    sanitized,
  };
}

/**
 * Validate email address
 */
export function validateEmail(email: string): ValidationResult {
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return validateString(email, {
    pattern: emailPattern,
    required: true,
    maxLength: 254, // RFC 5321 limit
  });
}

/**
 * Validate URL
 */
export function validateUrl(url: string): ValidationResult {
  try {
    const urlObj = new URL(url);
    // Only allow http and https protocols
    if (!["http:", "https:"].includes(urlObj.protocol)) {
      return {
        isValid: false,
        error: "Only HTTP and HTTPS URLs are allowed",
      };
    }
    return {
      isValid: true,
      sanitized: urlObj.toString(),
    };
  } catch {
    return {
      isValid: false,
      error: "Invalid URL format",
    };
  }
}

/**
 * Validate nonce (hex string)
 */
export function validateNonce(nonce: string): ValidationResult {
  const hexPattern = /^[a-fA-F0-9]+$/;
  return validateString(nonce, {
    pattern: hexPattern,
    required: true,
    minLength: 32,
    maxLength: 128,
  });
}

/**
 * Validate client ID
 */
export function validateClientId(clientId: string): ValidationResult {
  const clientIdPattern = /^[a-zA-Z0-9_-]+$/;
  return validateString(clientId, {
    pattern: clientIdPattern,
    required: true,
    minLength: 1,
    maxLength: 100,
  });
}

/**
 * Validate domain name
 */
export function validateDomain(domain: string): ValidationResult {
  const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return validateString(domain, {
    pattern: domainPattern,
    required: true,
    maxLength: 253, // RFC 1123 limit
  });
}

/**
 * Validate chain ID
 */
export function validateChainId(chainId: string): ValidationResult {
  const validChains = ["polkadot", "kusama", "westend", "rococo"];
  if (!validChains.includes(chainId)) {
    return {
      isValid: false,
      error: `Invalid chain ID. Must be one of: ${validChains.join(", ")}`,
    };
  }
  return {
    isValid: true,
    sanitized: chainId,
  };
}

/**
 * Sanitize HTML content
 */
export function sanitizeHtml(html: string): string {
  return html
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

/**
 * Validate and sanitize JSON input
 */
export function validateJson<T>(
  input: string,
  schema?: (obj: any) => obj is T
): ValidationResult & { data?: T } {
  try {
    const parsed = JSON.parse(input);
    
    if (schema && !schema(parsed)) {
      return {
        isValid: false,
        error: "JSON does not match expected schema",
      };
    }

    return {
      isValid: true,
      data: parsed,
    };
  } catch (error) {
    return {
      isValid: false,
      error: "Invalid JSON format",
    };
  }
}

/**
 * Rate limiting helper
 */
export class RateLimiter {
  private attempts: Map<string, { count: number; resetTime: number }> = new Map();
  private maxAttempts: number;
  private windowMs: number;

  constructor(maxAttempts: number = 5, windowMs: number = 60000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const attempt = this.attempts.get(key);

    if (!attempt || now > attempt.resetTime) {
      this.attempts.set(key, { count: 1, resetTime: now + this.windowMs });
      return true;
    }

    if (attempt.count >= this.maxAttempts) {
      return false;
    }

    attempt.count++;
    return true;
  }

  getRemainingAttempts(key: string): number {
    const attempt = this.attempts.get(key);
    if (!attempt) return this.maxAttempts;
    return Math.max(0, this.maxAttempts - attempt.count);
  }

  getResetTime(key: string): number | null {
    const attempt = this.attempts.get(key);
    return attempt ? attempt.resetTime : null;
  }
}
