# @synet/crypto


```bash
   _____                  _          _    _       _ _   
  / ____|                | |        | |  | |     (_) |  
 | |     _ __ _   _ _ __ | |_ ___   | |  | |_ __  _| |_ 
 | |    | '__| | | | '_ \| __/ _ \  | |  | | '_ \| | __|
 | |____| |  | |_| | |_) | || (_) | | |__| | | | | | |_ 
  \_____|_|   \__, | .__/ \__\___/   \____/|_| |_|_|\__|
               __/ | |                                  
              |___/|_|                                  

version:1.0.0
```

Foundational cryptographic operations implementing Unit Architecture with zero external dependencies.

## Installation

```bash
npm install @synet/crypto
```

## Overview

`@synet/crypto` provides battle-tested cryptographic primitives using Node.js native crypto for both Unit-based composition and serverless deployment. 

## Features

- **Symmetric Encryption** - AES-256-GCM with authentication
- **Digital Signatures** - RSA/EC signature creation and verification  
- **Cryptographic Hashing** - SHA-256, SHA-512, SHA3-512 support
- **Key Generation** - Secure symmetric keys and RSA/EC key pairs
- **Key Derivation** - PBKDF2, HKDF (RFC 5869), Scrypt support
- **Random Generation** - Cryptographically secure random bytes
- **Unit Architecture** - Teaching/learning capabilities for runtime composition
- **Serverless Ready** - Pure functions for Cloudflare Workers, AWS Lambda
- **Zero Dependencies** - Only Node.js native crypto, no external deps

## Quick Start

### Unit-Based Usage

```typescript
import { Crypto } from '@synet/crypto';

const crypto = Crypto.create();

// Simple operations (throw on error)
const key = crypto.generateKey(32);
const hash = crypto.hash('data to hash');
const keyPair = crypto.generateKeyPair('rsa', 2048);

// Complex operations (Result pattern)  
const encrypted = crypto.encrypt('sensitive data', key);
if (encrypted.isSuccess) {
  const decrypted = crypto.decrypt(encrypted.value, key);
  console.log('Decrypted:', decrypted.value);
}

// Key derivation
const derived = crypto.deriveKeyPBKDF2('password', salt, 100000);
console.log('Derived key:', derived.derivedKey);
```

### Serverless Functions

```typescript
import { encrypt, decrypt, hash, deriveKeyPBKDF2 } from '@synet/crypto/functions';

// Stateless operations perfect for serverless
const key = generateKey(32);
const encrypted = encrypt('data', key);
const hashed = hash('data');
const derived = deriveKeyPBKDF2('password', salt);
```

### Unit Learning/Teaching

```typescript
// Units can learn crypto capabilities
const crypto = Crypto.create();
const otherUnit = SomeUnit.create();

otherUnit.learn([crypto.teach()]);

// Now otherUnit can use crypto capabilities
const result = otherUnit.execute('crypto.encrypt', data, key);
```

## Architecture

Follows [Unit Architecture](https://github.com/synthetism/unit) with:

- **Immutable Value Objects** - No mutation, evolution creates new instances
- **Teaching Contracts** - Runtime capability sharing between units  
- **Error Boundaries** - Exceptions for simple ops, Results for complex ops
- **Consciousness Design** - Self-aware units with identity and capabilities



## License

MIT
