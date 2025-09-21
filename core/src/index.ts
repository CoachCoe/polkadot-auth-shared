import { SIWEAuthService } from './auth/siwe.js';
import { DEFAULT_CHAINS } from './chains/index.js';
import { getProviderById } from './providers/index.js';
import {
  AuthResult,
  ChainConfig,
  Challenge,
  PolkadotAuthConfig,
  PolkadotAuthInstance,
  Session,
  SIWEMessage,
  SIWESignature,
  WalletProvider,
} from './types/index.js';
import { randomBytes, randomUUID } from './utils/crypto.js';
import { validateString, validateEmail, validateUrl, validateNonce, validateClientId, validateDomain, validateChainId, RateLimiter } from './utils/validation.js';
import { createAuthError, handleError, logError, ErrorCode, ErrorSeverity, type AuthError } from './utils/errors.js';

export function createPolkadotAuth(config: PolkadotAuthConfig = {}): PolkadotAuthInstance {
  // SECURITY: Validate input configuration
  if (config.defaultChain) {
    const chainValidation = validateChainId(config.defaultChain);
    if (!chainValidation.isValid) {
      throw createAuthError(
        ErrorCode.VALIDATION_ERROR,
        `Invalid default chain: ${chainValidation.error}`,
        { context: 'createPolkadotAuth' }
      );
    }
  }

  const finalConfig: PolkadotAuthConfig = {
    defaultChain: 'polkadot',
    chains: DEFAULT_CHAINS,
    providers: ['polkadot-js', 'talisman', 'subwallet', 'nova'],
    session: {
      strategy: 'jwt',
      maxAge: 7 * 24 * 60 * 60,
    },
    database: {
      type: 'sqlite',
    },
    security: {
      enableNonce: true,
      enableDomainBinding: true,
      enableRequestTracking: true,
      challengeExpiration: 5 * 60, // 5 minutes
    },
    ...config,
  };

  const siweAuth = new SIWEAuthService(finalConfig.defaultChain);

  const enabledProviders: WalletProvider[] = [];

  if (finalConfig.providers) {
    for (const providerId of finalConfig.providers) {
      const provider = getProviderById(providerId);
      if (provider) {
        enabledProviders.push(provider);
      }
    }
  }

  if (finalConfig.customProviders) {
    enabledProviders.push(...finalConfig.customProviders);
  }

  const availableChains = finalConfig.chains || DEFAULT_CHAINS;

  return {
    config: finalConfig,

    async createChallenge(clientId: string, userAddress?: string): Promise<Challenge> {
      // SECURITY: Validate input parameters
      const clientIdValidation = validateClientId(clientId);
      if (!clientIdValidation.isValid) {
        throw createAuthError(
          ErrorCode.VALIDATION_ERROR,
          `Invalid client ID: ${clientIdValidation.error}`,
          { context: 'createChallenge' }
        );
      }

      if (userAddress) {
        const addressValidation = validateString(userAddress, {
          required: true,
          minLength: 47,
          maxLength: 48,
          pattern: /^[1-9A-HJ-NP-Za-km-z]{47,48}$/,
        });
        if (!addressValidation.isValid) {
          throw createAuthError(
            ErrorCode.INVALID_ADDRESS,
            `Invalid user address: ${addressValidation.error}`,
            { context: 'createChallenge' }
          );
        }
      }

      const chainId = finalConfig.defaultChain;
      return siweAuth.createChallenge(clientId, userAddress, chainId);
    },

    async verifySignature(signature: SIWESignature, challenge: Challenge): Promise<AuthResult> {
      return siweAuth.verifySIWESignature(signature, challenge);
    },

    async createSession(
      address: string,
      clientId: string,
      parsedMessage: SIWEMessage
    ): Promise<Session> {
      // SECURITY: Validate input parameters
      const addressValidation = validateString(address, {
        required: true,
        minLength: 47,
        maxLength: 48,
        pattern: /^[1-9A-HJ-NP-Za-km-z]{47,48}$/,
      });
      if (!addressValidation.isValid) {
        throw createAuthError(
          ErrorCode.INVALID_ADDRESS,
          `Invalid address: ${addressValidation.error}`,
          { context: 'createSession' }
        );
      }

      const clientIdValidation = validateClientId(clientId);
      if (!clientIdValidation.isValid) {
        throw createAuthError(
          ErrorCode.VALIDATION_ERROR,
          `Invalid client ID: ${clientIdValidation.error}`,
          { context: 'createSession' }
        );
      }

      // SECURITY: Use cryptographically secure random generation
      const sessionId = randomUUID();
      const accessToken = Array.from(randomBytes(32))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      const refreshToken = Array.from(randomBytes(32))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      const fingerprint = Array.from(randomBytes(16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      const now = Date.now();
      const accessTokenExpiresAt = now + 15 * 60 * 1000; // 15 minutes
      const refreshTokenExpiresAt = now + 7 * 24 * 60 * 60 * 1000; // 7 days

      const session: Session = {
        id: sessionId,
        address: addressValidation.sanitized!,
        clientId: clientIdValidation.sanitized!,
        accessToken,
        refreshToken,
        accessTokenId: randomUUID(),
        refreshTokenId: randomUUID(),
        fingerprint,
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        createdAt: now,
        lastUsedAt: now,
        isActive: true,
      };

      return session;
    },

    async getSession(accessToken: string): Promise<Session | null> {
      return null;
    },

    async refreshSession(refreshToken: string): Promise<Session | null> {
      return null;
    },

    async invalidateSession(sessionId: string): Promise<void> {},

    getProviders(): WalletProvider[] {
      return enabledProviders;
    },

    getChains(): ChainConfig[] {
      return availableChains;
    },
  };
}

export * from './types/index.js';

export {
  createCustomProvider,
  DEFAULT_PROVIDERS,
  getAvailableProviders,
  getProviderById,
  novaWalletProvider,
  polkadotJsProvider,
  subWalletProvider,
  talismanProvider,
} from './providers/index.js';

export {
  DEFAULT_CHAINS,
  getAllRpcUrls,
  getChainById,
  getDefaultChain,
  getMainnetChains,
  getSecureChainConfig,
  getTestnetChains,
  validateChainConfig,
} from './chains/index.js';

export { SIWEAuthService } from './auth/siwe.js';

export { AuthService, authService } from './services/authService.js';
export { ErrorService } from './services/errorService.js';
export { createPapiClient, PapiClientService } from './services/papiClient.js';
export { WalletProviderService, walletProviderService } from './services/walletProviderService.js';

// Remittance services
export { ComplianceService } from './services/complianceService.js';
export {
  createExchangeRateService,
  DEFAULT_EXCHANGE_RATE_CONFIG,
  ExchangeRateService,
} from './services/exchangeRateService.js';
export type { ExchangeRateConfig, ExchangeRateProvider } from './services/exchangeRateService.js';
export { RemittanceAuthService } from './services/remittanceAuthService.js';
export { RemittanceService } from './services/remittanceService.js';

// Configuration
export {
  ProductionConfigManager,
  configManager,
  getConfig,
  validateConfig,
} from './config/productionConfig.js';
export type {
  ProductionConfig,
  SecurityConfig,
  DatabaseConfig,
  RemittanceConfig,
  ChainConfig,
  LoggingConfig,
} from './config/productionConfig.js';

// Export validation utilities
export {
  validateString,
  validateEmail,
  validateUrl,
  validateNonce,
  validateClientId,
  validateDomain,
  validateChainId,
  RateLimiter,
} from './utils/validation.js';

// Export error handling utilities
export {
  createAuthError,
  handleError,
  logError,
  sanitizeErrorForClient,
  ErrorCode,
  ErrorSeverity,
  type AuthError,
} from './utils/errors.js';

// Export crypto utilities
export {
  randomBytes,
  randomUUID,
  createHash,
  createHmac,
} from './utils/crypto.js';

export default createPolkadotAuth;
