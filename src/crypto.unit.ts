/**
 * Cryptimport { Unit, type UnitProps, type TeachingContract, createUnitSchema } from '@synet/unit';
import { Result } from './result.js';
import { 
  createHash, 
  createCipheriv, 
  createDecipheriv, 
  generateKeyPairSync, 
  createSign,
  createVerify,
  randomBytes
} from 'crypto';undational Cryptographic Operations
 * 
 * Following Unit Architecture Doctrine v1.0.5
 * Doctrine #20: Do one thing well, then teach
 * 
 * ONE THING: Symmetric/Asymmetric encryption + digital signatures using Node.js native crypto
 * TEACH: Enable runtime learning of crypto capabilities for other units
 * 
 * APPROACH: Fail fast with exceptions for simple operations, Result for complex multi-step operations
 */

import { Unit, type UnitProps, type TeachingContract, createUnitSchema } from '@synet/unit';
import { Result } from './result.js';
import { 
  createHash, 
  createCipheriv, 
  createDecipheriv, 
  generateKeyPairSync, 
  createSign,
  createVerify,
  randomBytes 
} from 'node:crypto';

// Doctrine #13: TYPE HIERARCHY CONSISTENCY (Config → Props → State → Output)

/**
 * External input configuration for static create()
 */
export interface CryptoConfig {
  algorithm?: 'aes-256-gcm' | 'aes-128-gcm';
  keySize?: 256 | 512 | 1024 | 2048 | 4096;
  hashAlgorithm?: 'sha256' | 'sha512' | 'sha3-512';
  metadata?: Record<string, unknown>;
}

/**
 * Internal immutable props after validation
 */
export interface CryptoProps extends UnitProps {
  algorithm: string;
  keySize: number;
  hashAlgorithm: string;
  operationCount: number;
}

/**
 * Domain output for external consumption
 */
export interface CryptoCapabilities {
  encrypt: string;
  decrypt: string;
  sign: string;
  verify: string;
  hash: string;
  generateKey: string;
  generateKeyPair: string;
}

/**
 * Encrypted data result
 */
export interface EncryptedData {
  data: string;
  iv: string;
  tag?: string;
  algorithm: string;
}

/**
 * Key pair result
 */
export interface KeyPair {
  publicKey: string;
  privateKey: string;
  algorithm: string;
  keySize: number;
}

/**
 * Hash result
 */
export interface HashResult {
  hash: string;
  algorithm: string;
  input: string;
  timestamp: Date;
}

/**
 * Crypto Implementation
 * 
 * Doctrine #1: ZERO DEPENDENCY (only Node.js native crypto)
 * Doctrine #17: VALUE OBJECT FOUNDATION (immutable with identity and capabilities)
 */
export class Crypto extends Unit<CryptoProps> {
  
  // Doctrine #4: CREATE NOT CONSTRUCT (protected constructor)
  protected constructor(props: CryptoProps) {
    super(props);
  }

  // Doctrine #4: CREATE NOT CONSTRUCT (static create with validation)
  static create(config: CryptoConfig = {}): Crypto {
    // Doctrine #3: PROPS CONTAIN EVERYTHING (validate and transform config to props)
    const props: CryptoProps = {
      // Doctrine #7: EVERY UNIT MUST HAVE DNA
      dna: createUnitSchema({ 
        id: 'crypto', 
        version: '1.0.0' 
      }),
      algorithm: config.algorithm || 'aes-256-gcm',
      keySize: config.keySize || 2048,
      hashAlgorithm: config.hashAlgorithm || 'sha256',
      operationCount: 0,
      created: new Date(),
      metadata: config.metadata || {}
    };
    
    return new Crypto(props);
  }

  // Doctrine #11: ALWAYS HELP (living documentation)
  help(): void {
    console.log(`
🔐 Crypto Unit [${this.dna.id}] v${this.dna.version} - Foundational Cryptographic Engine

IDENTITY: ${this.whoami()}
ALGORITHM: ${this.props.algorithm}
KEY SIZE: ${this.props.keySize}
HASH: ${this.props.hashAlgorithm}
OPERATIONS: ${this.props.operationCount}

NATIVE CAPABILITIES:
• encrypt(data, key) - Symmetric encryption with AES (Result for complex operation)
• decrypt(encrypted, key) - Symmetric decryption (Result for complex operation)
• hash(data, algorithm?) - Cryptographic hashing (throws on error)
• generateKey(size?) - Generate random encryption key (throws on error)
• generateKeyPair(algorithm?, keySize?) - Generate RSA/EC key pairs (throws on error)
• sign(data, privateKey) - Digital signatures (Result for complex operation)
• verify(data, signature, publicKey) - Signature verification (Result for complex operation)
• randomBytes(size) - Secure random bytes generation (throws on error)

SUPPORTED ALGORITHMS:
• Symmetric: ${this.props.algorithm}
• Hash: ${this.props.hashAlgorithm}
• Asymmetric: RSA, EC (secp256k1, prime256v1)

I TEACH:
• encrypt(data, key) - Symmetric encryption capability
• decrypt(encrypted, key) - Symmetric decryption capability  
• hash(data) - Cryptographic hashing capability
• sign(data, privateKey) - Digital signing capability
• verify(data, signature, publicKey) - Signature verification capability

USAGE EXAMPLES:
  const crypto = Crypto.create();
  
  // Simple operations (throw on error)
  const key = crypto.generateKey();
  const hashResult = crypto.hash('data to hash');
  const keyPair = crypto.generateKeyPair();
  
  // Complex operations (Result pattern)
  const encrypted = await crypto.encrypt('sensitive data', key);
  if (encrypted.isSuccess) {
    const decrypted = await crypto.decrypt(encrypted.value, key);
  }

LEARNING CAPABILITIES:
Other units can learn from me:
  unit.learn([crypto.teach()]);
  unit.execute('crypto.encrypt', data, key);

ARCHITECTURE: One unit, one goal - cryptographic excellence with zero dependencies
`);
  }

  // Doctrine #2: TEACH/LEARN PARADIGM (every unit must teach)
  // Doctrine #9: ALWAYS TEACH (explicit capability binding)
  // Doctrine #19: CAPABILITY LEAKAGE PREVENTION (teach only native capabilities)
  teach(): TeachingContract {
    return {
      // Doctrine #12: NAMESPACE EVERYTHING (unitId for namespacing)
      unitId: this.dna.id,
      capabilities: {
        // Native cryptographic capabilities only - wrapped for unknown[] compatibility
        encrypt: ((...args: unknown[]) => this.encrypt(args[0] as string, args[1] as string)) as (...args: unknown[]) => unknown,
        decrypt: ((...args: unknown[]) => this.decrypt(args[0] as EncryptedData, args[1] as string)) as (...args: unknown[]) => unknown,
        hash: ((...args: unknown[]) => this.hash(args[0] as string, args[1] as string)) as (...args: unknown[]) => unknown,
        sign: ((...args: unknown[]) => this.sign(args[0] as string, args[1] as string)) as (...args: unknown[]) => unknown,
        verify: ((...args: unknown[]) => this.verify(args[0] as string, args[1] as string, args[2] as string)) as (...args: unknown[]) => unknown,
        generateKey: ((...args: unknown[]) => this.generateKey(args[0] as number)) as (...args: unknown[]) => unknown,
        generateKeyPair: ((...args: unknown[]) => this.generateKeyPair(args[0] as 'rsa' | 'ec', args[1] as number)) as (...args: unknown[]) => unknown,
        randomBytes: ((...args: unknown[]) => this.randomBytes(args[0] as number)) as (...args: unknown[]) => unknown,
        
        // Metadata access
        getAlgorithm: (() => this.props.algorithm) as (...args: unknown[]) => unknown,
        getKeySize: (() => this.props.keySize) as (...args: unknown[]) => unknown,
        getHashAlgorithm: (() => this.props.hashAlgorithm) as (...args: unknown[]) => unknown,
        getOperationCount: (() => this.props.operationCount) as (...args: unknown[]) => unknown
      }
    };
  }

  // Doctrine #8: PURE FUNCTION HEARTS (core logic as pure functions)
  // Doctrine #14: ERROR BOUNDARY CLARITY (Result for complex operations, throw for simple ones)
  
  /**
   * Symmetric encryption using AES (Result - complex multi-step operation)
   */
  async encrypt(data: string, key: string): Promise<Result<EncryptedData>> {
    try {
      // Doctrine #8: Pure function heart
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.props.algorithm, Buffer.from(key, 'hex'), iv);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Handle GCM authentication tag
      let tag: string | undefined;
      if (this.props.algorithm.includes('gcm')) {
        tag = (cipher as any).getAuthTag().toString('hex');
      }
      
      return Result.success({
        data: encrypted,
        iv: iv.toString('hex'),
        tag,
        algorithm: this.props.algorithm
      });
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Encryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Symmetric decryption using AES (Result - complex multi-step operation)
   */
  async decrypt(encrypted: EncryptedData, key: string): Promise<Result<string>> {
    try {
      const decipher = createDecipheriv(
        encrypted.algorithm,
        Buffer.from(key, 'hex'),
        Buffer.from(encrypted.iv, 'hex')
      );
      
      // Handle GCM authentication tag
      if (encrypted.tag && encrypted.algorithm.includes('gcm')) {
        (decipher as any).setAuthTag(Buffer.from(encrypted.tag, 'hex'));
      }
      
      let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return Result.success(decrypted);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Cryptographic hashing (throw on error - simple operation)
   */
  hash(data: string, algorithm?: string): HashResult {
    const hashAlg = algorithm || this.props.hashAlgorithm;
    const hash = createHash(hashAlg);
    hash.update(data);
    
    return {
      hash: hash.digest('hex'),
      algorithm: hashAlg,
      input: data,
      timestamp: new Date()
    };
  }

  /**
   * Generate symmetric encryption key (throw on error - simple operation)
   */
  generateKey(size: number = 32): string {
    return randomBytes(size).toString('hex');
  }

  /**
   * Generate asymmetric key pair (throw on error - simple operation)
   */
  generateKeyPair(algorithm: 'rsa' | 'ec' = 'rsa', keySize?: number): KeyPair {
    const actualKeySize = keySize || this.props.keySize;
    
    if (algorithm === 'rsa') {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: actualKeySize,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      return {
        publicKey: publicKey as string,
        privateKey: privateKey as string,
        algorithm,
        keySize: actualKeySize
      };
    } else {
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      return {
        publicKey: publicKey as string,
        privateKey: privateKey as string,
        algorithm,
        keySize: 256 // EC keys have fixed sizes based on curve
      };
    }
  }

  /**
   * Digital signature creation (Result - complex operation with multiple failure modes)
   */
  async sign(data: string, privateKey: string): Promise<Result<string>> {
    try {
      const signer = createSign('sha256');
      signer.update(data);
      signer.end();
      
      const signature = signer.sign(privateKey, 'hex');
      return Result.success(signature);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Signing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Digital signature verification (Result - complex operation with multiple failure modes)
   */
  async verify(data: string, signature: string, publicKey: string): Promise<Result<boolean>> {
    try {
      const verifier = createVerify('sha256');
      verifier.update(data);
      verifier.end();
      
      const isValid = verifier.verify(publicKey, signature, 'hex');
      return Result.success(isValid);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Generate secure random bytes (throw on error - simple operation)
   */
  randomBytes(size: number): string {
    return randomBytes(size).toString('hex');
  }

  // Doctrine #22: STATELESS OPERATIONS (expose current capabilities)
  capabilities(): string[] {
    return [
      'encrypt', 'decrypt', 'hash', 'sign', 'verify', 
      'generateKey', 'generateKeyPair', 'randomBytes',
      `algorithm: ${this.props.algorithm}`,
      `keySize: ${this.props.keySize}`,
      `hashAlgorithm: ${this.props.hashAlgorithm}`,
      `operations: ${this.props.operationCount}`
    ];
  }

  // Doctrine #13: TYPE HIERARCHY CONSISTENCY (domain output)
  toDomain(): CryptoCapabilities {
    return {
      encrypt: 'aes-256-gcm',
      decrypt: 'aes-256-gcm', 
      sign: 'rsa-sha256',
      verify: 'rsa-sha256',
      hash: this.props.hashAlgorithm,
      generateKey: 'random-bytes',
      generateKeyPair: 'rsa'
    };
  }

  // Standard unit identification
  whoami(): string {
    return `CryptoUnit[${this.dna.id}@${this.dna.version}]`;
  }

  // JSON serialization (no private keys exposed)
  toJSON(): Record<string, unknown> {
    return {
      type: 'CryptoUnit',
      dna: this.dna,
      algorithm: this.props.algorithm,
      keySize: this.props.keySize,
      hashAlgorithm: this.props.hashAlgorithm,
      operationCount: this.props.operationCount,
      capabilities: this.capabilities(),
      created: this.props.created
    };
  }
}
