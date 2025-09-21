import * as CryptoJS from "crypto-js";

export interface CryptoUtils {
  randomBytes: (size: number) => Uint8Array;
  createHash: (algorithm: string) => {
    update: (data: string | Uint8Array) => any;
    digest: (encoding?: string) => string;
  };
  randomUUID: () => string;
  createHmac: (
    algorithm: string,
    key: string | Uint8Array,
  ) => {
    update: (data: string | Uint8Array) => any;
    digest: (encoding?: string) => string;
  };
}

class BrowserCryptoUtils implements CryptoUtils {
  randomBytes(size: number): Uint8Array {
    const array = new Uint8Array(size);
    if (
      typeof window !== "undefined" &&
      window.crypto &&
      window.crypto.getRandomValues
    ) {
      window.crypto.getRandomValues(array);
    } else {
      // SECURITY FIX: Use crypto-js for secure random generation instead of Math.random()
      const secureRandom = CryptoJS.lib.WordArray.random(size);
      for (let i = 0; i < size; i++) {
        array[i] = secureRandom.words[Math.floor(i / 4)] >>> (8 * (3 - (i % 4))) & 0xff;
      }
    }
    return array;
  }

  createHash(algorithm: string) {
    let result: CryptoJS.lib.WordArray | null = null;
    let input: string | CryptoJS.lib.WordArray | null = null;

    return {
      update: (data: string | Uint8Array) => {
        input =
          typeof data === "string" ? data : CryptoJS.lib.WordArray.create(data);
        return this;
      },
      digest: (encoding: string = "hex") => {
        if (!input) {
          throw new Error("No data provided to hash");
        }

        switch (algorithm.toLowerCase()) {
          case "sha256":
            result = CryptoJS.SHA256(input);
            break;
          case "sha512":
            result = CryptoJS.SHA512(input);
            break;
          case "md5":
            result = CryptoJS.MD5(input);
            break;
          default:
            throw new Error(`Unsupported hash algorithm: ${algorithm}`);
        }

        if (encoding === "hex") {
          return result.toString(CryptoJS.enc.Hex);
        } else if (encoding === "base64") {
          return result.toString(CryptoJS.enc.Base64);
        } else {
          return result.toString();
        }
      },
    };
  }

  randomUUID(): string {
    if (
      typeof window !== "undefined" &&
      window.crypto &&
      window.crypto.randomUUID
    ) {
      return window.crypto.randomUUID();
    }

    // SECURITY FIX: Use crypto-js for secure UUID generation
    const randomBytes = CryptoJS.lib.WordArray.random(16);
    const hex = randomBytes.toString(CryptoJS.enc.Hex);
    
    return [
      hex.substring(0, 8),
      hex.substring(8, 12),
      '4' + hex.substring(13, 16), // Version 4
      ((parseInt(hex.substring(16, 17), 16) & 0x3) | 0x8).toString(16) + hex.substring(17, 20), // Variant bits
      hex.substring(20, 32)
    ].join('-');
  }

  createHmac(algorithm: string, key: string | Uint8Array) {
    const keyString =
      typeof key === "string" ? key : CryptoJS.lib.WordArray.create(key);
    let result: CryptoJS.lib.WordArray | null = null;
    let input: string | CryptoJS.lib.WordArray | null = null;

    return {
      update: (data: string | Uint8Array) => {
        input =
          typeof data === "string" ? data : CryptoJS.lib.WordArray.create(data);
        return this;
      },
      digest: (encoding: string = "hex") => {
        if (!input) {
          throw new Error("No data provided to HMAC");
        }

        switch (algorithm.toLowerCase()) {
          case "sha256":
            result = CryptoJS.HmacSHA256(input, keyString);
            break;
          case "sha512":
            result = CryptoJS.HmacSHA512(input, keyString);
            break;
          default:
            throw new Error(`Unsupported HMAC algorithm: ${algorithm}`);
        }

        if (encoding === "hex") {
          return result.toString(CryptoJS.enc.Hex);
        } else if (encoding === "base64") {
          return result.toString(CryptoJS.enc.Base64);
        } else {
          return result.toString();
        }
      },
    };
  }
}

class NodeCryptoUtils implements CryptoUtils {
  private crypto: typeof import("crypto") | null = null;

  constructor() {
    // Dynamic import for Node.js crypto
    if (typeof window === "undefined") {
      try {
        this.crypto = require("crypto");
      } catch (error) {
        console.warn(
          "Node.js crypto not available, falling back to browser crypto",
        );
        this.crypto = null;
      }
    }
  }

  randomBytes(size: number): Uint8Array {
    if (!this.crypto) {
      throw new Error("Node.js crypto not available");
    }
    return this.crypto.randomBytes(size);
  }

  createHash(algorithm: string) {
    if (!this.crypto) {
      throw new Error("Node.js crypto not available");
    }
    const hash = this.crypto.createHash(algorithm);
    return {
      update: (data: string | Uint8Array) => {
        hash.update(data);
        return this;
      },
      digest: (encoding: string = "hex") => {
        return hash.digest(encoding as any);
      },
    };
  }

  randomUUID(): string {
    if (!this.crypto) {
      throw new Error("Node.js crypto not available");
    }
    return this.crypto.randomUUID();
  }

  createHmac(algorithm: string, key: string | Uint8Array) {
    if (!this.crypto) {
      throw new Error("Node.js crypto not available");
    }
    const hmac = this.crypto.createHmac(algorithm, key);
    return {
      update: (data: string | Uint8Array) => {
        hmac.update(data);
        return this;
      },
      digest: (encoding: string = "hex") => {
        return hmac.digest(encoding as any);
      },
    };
  }
}

// Detect environment and export appropriate crypto utils
export const cryptoUtils: CryptoUtils = (() => {
  try {
    // Try to require Node.js crypto module
    require("crypto");
    return new NodeCryptoUtils();
  } catch {
    // Fall back to browser-compatible implementation
    return new BrowserCryptoUtils();
  }
})();

// Export individual functions for convenience
export const randomBytes = (size: number) => cryptoUtils.randomBytes(size);
export const createHash = (algorithm: string) =>
  cryptoUtils.createHash(algorithm);
export const randomUUID = () => cryptoUtils.randomUUID();
export const createHmac = (algorithm: string, key: string | Uint8Array) =>
  cryptoUtils.createHmac(algorithm, key);