# @polkadot-auth/core

> 🚀 **Shared Components & Utilities** for the Polkadot Authentication Ecosystem

A comprehensive, framework-agnostic core library that provides common functionality needed by Polkadot authentication services, eliminating code duplication and ensuring consistency across the ecosystem.

## ✨ Features

- 🔐 **SIWE-Style Authentication**: EIP-4361 compliant authentication messages
- 🏗️ **Multi-Wallet Support**: Polkadot.js, Talisman, SubWallet, Nova Wallet
- 🌐 **Multi-Chain Support**: Polkadot, Kusama, Westend, Rococo with backup RPC endpoints
- 🛡️ **Security-First Design**: Nonce-based replay protection, domain binding, request tracking
- 📱 **Cross-Platform**: Works in both browser and Node.js environments
- 🔧 **TypeScript First**: Full type safety and IntelliSense support
- 🏢 **Enterprise Ready**: Production configuration management and audit logging
- 💰 **Remittance Services**: Built-in compliance and exchange rate services

## 🎯 Purpose

This package serves as the **foundational library** for the Polkadot authentication ecosystem, providing:

- **Common Types & Interfaces** - Shared TypeScript definitions
- **Cryptographic Utilities** - Cross-platform crypto functions
- **Chain Management** - Multi-chain support with security features
- **Wallet Providers** - Standardized wallet integration interfaces
- **Authentication Services** - Core auth logic and session management
- **Remittance Services** - Compliance and exchange rate functionality

## 📦 Installation

```bash
npm install @polkadot-auth/core
```

## 🚀 Quick Start

### Basic Authentication

```typescript
import { createPolkadotAuth } from '@polkadot-auth/core';

// Create auth instance with default configuration
const auth = createPolkadotAuth();

// Create a challenge
const challenge = await auth.createChallenge('my-app');

console.log(challenge.message);
// Output:
// polkadot-auth.localhost wants you to sign in with your Polkadot account:
// 5EJP9eSB1HpzjpuCJrna8KMcA6mmgaT8W4gSmwHaVDn25gHQ
//
// Sign this message to authenticate with Polkadot SSO
//
// URI: http://localhost:3000
// Version: 1
// Chain ID: polkadot
// Nonce: a1b2c3d4e5f6...
// Issued At: 2025-01-24T18:30:00.000Z
// Expiration Time: 2025-01-24T18:35:00.000Z
// Request ID: 12345678-1234-1234-1234-123456789abc
// Resources:
// - https://polkadot-auth.localhost/credentials
// - https://polkadot-auth.localhost/profile
```

### Using Individual Services

```typescript
import { 
  authService, 
  walletProviderService, 
  createExchangeRateService,
  configManager 
} from '@polkadot-auth/core';

// Use authentication service
const result = await authService.authenticateUser(address, signature);

// Get available wallet providers
const providers = await walletProviderService.getAvailableProviders();

// Create exchange rate service
const exchangeService = createExchangeRateService({
  provider: 'coingecko',
  apiKey: 'your-api-key'
});

// Get production configuration
const config = configManager.getConfig();
```

## 🏗️ Architecture

### Core Components

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| **SIWEAuthService** | Authentication logic | SIWE message generation, signature verification |
| **Wallet Providers** | Wallet integration | Multi-wallet support, standardized interface |
| **Chain Management** | Multi-chain support | Security-focused config, backup RPC endpoints |
| **Session Management** | Session handling | JWT-based sessions, refresh tokens |
| **Remittance Services** | Financial operations | Compliance, exchange rates, treasury management |
| **Configuration** | Production config | Environment management, security settings |

### Supported Chains

| Chain | RPC Endpoint | SS58 Format | Type | Backup RPCs |
|-------|-------------|-------------|------|-------------|
| **Polkadot** | `wss://rpc.polkadot.io` | 0 | Mainnet | 3 backup endpoints |
| **Kusama** | `wss://kusama-rpc.polkadot.io` | 2 | Mainnet | 3 backup endpoints |
| **Westend** | `wss://westend-rpc.polkadot.io` | 42 | Testnet | 2 backup endpoints |
| **Rococo** | `wss://rococo-rpc.polkadot.io` | 42 | Testnet | 1 backup endpoint |

### Supported Wallets

| Wallet | Type | Features |
|--------|------|----------|
| **Polkadot.js** | Browser Extension | Official extension, full feature support |
| **Talisman** | Browser Extension | Popular wallet, advanced features |
| **SubWallet** | Browser Extension | Feature-rich, multi-chain support |
| **Nova Wallet** | Mobile + Browser | Mobile app with browser bridge |

## 🔧 Configuration

### Basic Configuration

```typescript
import { createPolkadotAuth } from '@polkadot-auth/core';

const auth = createPolkadotAuth({
  defaultChain: 'polkadot',
  providers: ['polkadot-js', 'talisman'],
  session: {
    strategy: 'jwt',
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },
  security: {
    enableNonce: true,
    enableDomainBinding: true,
    challengeExpiration: 5 * 60, // 5 minutes
  },
});
```

### Production Configuration

```typescript
import { configManager } from '@polkadot-auth/core';

// Load production configuration
const config = configManager.getConfig({
  environment: 'production',
  database: {
    type: 'postgres',
    url: process.env.DATABASE_URL
  },
  security: {
    enableAuditLogging: true,
    enableRateLimiting: true
  }
});
```

## 🔐 Security Features

### SIWE-Style Messages

Messages follow the EIP-4361 standard with Polkadot-specific adaptations:

```
polkadot-auth.localhost wants you to sign in with your Polkadot account:
5EJP9eSB1HpzjpuCJrna8KMcA6mmgaT8W4gSmwHaVDn25gHQ

Sign this message to authenticate with Polkadot SSO

URI: http://localhost:3000
Version: 1
Chain ID: polkadot
Nonce: a1b2c3d4e5f6...
Issued At: 2025-01-24T18:30:00.000Z
Expiration Time: 2025-01-24T18:35:00.000Z
Request ID: 12345678-1234-1234-1234-123456789abc
Resources:
- https://polkadot-auth.localhost/credentials
- https://polkadot-auth.localhost/profile
```

### Security Validations

- ✅ **Nonce Verification** - Prevents replay attacks
- ✅ **Domain Binding** - Ensures messages are for the correct domain
- ✅ **Expiration Checking** - Prevents use of expired challenges
- ✅ **Address Validation** - Validates Polkadot address format
- ✅ **Request Tracking** - Unique request IDs for audit trails
- ✅ **Rate Limiting** - Configurable rate limiting
- ✅ **Audit Logging** - Comprehensive security audit trails

## 💰 Remittance Services

### Exchange Rate Service

```typescript
import { createExchangeRateService } from '@polkadot-auth/core';

const exchangeService = createExchangeRateService({
  provider: 'coingecko',
  apiKey: 'your-api-key',
  updateInterval: 60000, // 1 minute
  supportedCurrencies: ['DOT', 'KSM', 'USD', 'EUR']
});

// Get current exchange rate
const rate = await exchangeService.getExchangeRate('DOT', 'USD');
console.log(`1 DOT = ${rate} USD`);
```

### Compliance Service

```typescript
import { ComplianceService } from '@polkadot-auth/core';

const compliance = new ComplianceService({
  enableSanctionsScreening: true,
  enableKYC: true,
  enableAML: true
});

// Check if address is compliant
const isCompliant = await compliance.checkAddress(address);
```

## 🔌 Extending

### Custom Wallet Provider

```typescript
import { createCustomProvider } from '@polkadot-auth/core';

const customProvider = createCustomProvider({
  id: 'my-wallet',
  name: 'My Custom Wallet',
  description: 'A custom wallet implementation',
  connect: async () => {
    // Implement wallet connection logic
    return {
      provider: customProvider,
      accounts: [],
      signMessage: async message => {
        // Implement message signing
        return 'signed-message';
      },
      disconnect: async () => {
        // Implement disconnect logic
      },
    };
  },
  isAvailable: () => {
    // Check if wallet is available
    return true;
  },
});

const auth = createPolkadotAuth({
  customProviders: [customProvider],
});
```

### Custom Chain

```typescript
const customChain = {
  id: 'my-parachain',
  name: 'My Parachain',
  rpcUrl: 'wss://my-parachain-rpc.com',
  ss58Format: 42,
  decimals: 12,
  symbol: 'MYT',
  isTestnet: false,
  backupRpcUrls: [
    'wss://backup1.my-parachain.com',
    'wss://backup2.my-parachain.com'
  ],
  security: {
    minConfirmationBlocks: 2,
    maxRetries: 3,
    timeout: 30000,
    enableStrictValidation: true
  }
};

const auth = createPolkadotAuth({
  chains: [customChain],
  defaultChain: 'my-parachain',
});
```

## 📚 API Reference

### Core Functions

#### `createPolkadotAuth(config?)`

Creates a new Polkadot Auth instance.

**Parameters:**
- `config` (optional): `PolkadotAuthConfig` - Configuration object

**Returns:** `PolkadotAuthInstance`

### Services

#### `authService`
Core authentication service with user management.

#### `walletProviderService`
Wallet provider management and detection.

#### `createExchangeRateService(config)`
Creates an exchange rate service instance.

#### `ComplianceService`
Compliance and regulatory checking service.

#### `configManager`
Production configuration management.

### Types

#### `PolkadotAuthConfig`
Main configuration interface for the auth instance.

#### `ChainConfig`
Chain configuration with security settings.

#### `WalletProvider`
Standardized wallet provider interface.

#### `Session`
User session with JWT tokens and metadata.

#### `Challenge`
Authentication challenge with SIWE message.

## 🧪 Development

### Building

```bash
# Clean build artifacts
npm run clean

# Build ESM and CommonJS
npm run build

# Watch mode for development
npm run dev
```

### Code Quality

```bash
# Format code
npm run format

# Check formatting
npm run format:check

# Type checking
npm run type-check
```

### Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

## 📦 Package Structure

```
@polkadot-auth/core/
├── src/
│   ├── auth/           # Authentication logic
│   ├── chains/         # Chain management
│   ├── config/         # Configuration management
│   ├── contracts/      # Smart contract interfaces
│   ├── providers/      # Wallet providers
│   ├── services/       # Core services
│   ├── types/          # TypeScript definitions
│   ├── utils/          # Utility functions
│   └── index.ts        # Main exports
├── dist/               # ESM build output
├── dist-cjs/           # CommonJS build output
└── package.json
```

## 🔗 Related Packages

This package is part of the Polkadot Authentication ecosystem:

- **`@polkadot-auth/sso`** - SSO server implementation
- **`@polkadot-auth/password-manager`** - Password management system
- **`@polkadot-auth/express`** - Express.js adapter
- **`@polkadot-auth/next`** - Next.js adapter
- **`@polkadot-auth/ui`** - React UI components

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`npm test`)
6. Format your code (`npm run format`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/CoachCoe/polkadot-auth-shared)
- 🐛 [Report Issues](https://github.com/CoachCoe/polkadot-auth-shared/issues)
- 💬 [Discussions](https://github.com/CoachCoe/polkadot-auth-shared/discussions)

## 🏷️ Version

Current version: `0.1.0`

---

**Built with ❤️ for the Polkadot ecosystem**