/**
 * Foundational Cryptographic Operations
 *
 * Following Unit Architecture v1.0.6
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
  randomBytes,
  pbkdf2Sync,
  createHmac,
  scryptSync
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
  deriveKeyPBKDF2: string;
  deriveKeyHKDF: string;
  deriveKeyScrypt: string;
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
 * Key derivation result
 */
export interface KeyDerivationResult {
  derivedKey: string;
  salt: string;
  algorithm: string;
  iterations?: number;
  keyLength: number;
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


Hi, I am Crypto Unit [${this.dna.id}] v${this.dna.version} - Foundational Cryptographic Service

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
• deriveKeyPBKDF2(password, salt, iterations?) - PBKDF2 key derivation (throws on error)
• deriveKeyHKDF(material, salt, info?, length?) - HKDF key derivation (throws on error)  
• deriveKeyScrypt(password, salt, length?, options?) - Scrypt key derivation (throws on error)

SUPPORTED ALGORITHMS:
• Symmetric: ${this.props.algorithm}
• Hash: ${this.props.hashAlgorithm}
• Asymmetric: RSA, EC (prime256v1)

I TEACH:
• encrypt(data, key) - Symmetric encryption capability
• decrypt(encrypted, key) - Symmetric decryption capability  
• hash(data) - Cryptographic hashing capability
• sign(data, privateKey) - Digital signing capability
• verify(data, signature, publicKey) - Signature verification capability
• deriveKeyPBKDF2(password, salt, iterations) - PBKDF2 key derivation capability
• deriveKeyHKDF(material, salt, info, length) - HKDF key derivation capability
• deriveKeyScrypt(password, salt, length, options) - Scrypt key derivation capability

USAGE EXAMPLES:
  const crypto = Crypto.create();
  
  // Simple operations (throw on error)
  const key = crypto.generateKey();
  const hashResult = crypto.hash('data to hash');
  const keyPair = crypto.generateKeyPair();
  
  // Complex operations (Result pattern, now synchronous!)
  const encrypted = crypto.encrypt('sensitive data', key);
  if (encrypted.isSuccess) {
    const decrypted = crypto.decrypt(encrypted.value, key);
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
        encrypt: (...args: unknown[]) => this.encrypt(args[0] as string, args[1] as string),
        decrypt: (...args: unknown[]) => this.decrypt(args[0] as EncryptedData, args[1] as string),
        hash: (...args: unknown[]) => this.hash(args[0] as string, args[1] as string),
        sign: (...args: unknown[]) => this.sign(args[0] as string, args[1] as string),
        verify: (...args: unknown[]) => this.verify(args[0] as string, args[1] as string, args[2] as string),
        generateKey: (...args: unknown[]) => this.generateKey(args[0] as number),
        generateKeyPair: (...args: unknown[]) => this.generateKeyPair(args[0] as 'rsa' | 'ec', args[1] as number),
        randomBytes: (...args: unknown[]) => this.randomBytes(args[0] as number),
        
        // Key derivation capabilities
        deriveKeyPBKDF2: (...args: unknown[]) => this.deriveKeyPBKDF2(args[0] as string, args[1] as string, args[2] as number),
        deriveKeyHKDF: (...args: unknown[]) => this.deriveKeyHKDF(args[0] as string, args[1] as string, args[2] as string, args[3] as number),
        deriveKeyScrypt: (...args: unknown[]) => this.deriveKeyScrypt(args[0] as string, args[1] as string, args[2] as number, args[3] as { N?: number; r?: number; p?: number }),
        
        // Metadata access
        getAlgorithm: () => this.getAlgorithm.bind(this),
        getKeySize: () => this.getKeySize.bind(this),
        getHashAlgorithm: () => this.getHashAlgorithm.bind(this),
      }
    };
  }

  getAlgorithm() {
    return this.props.algorithm;
  }

  getKeySize() {
    return this.props.keySize;
  }
  getHashAlgorithm() {
    return this.props.hashAlgorithm;
  }

  /**
   * Symmetric encryption using AES (Result - complex multi-step operation)
   */
  encrypt(data: string, key: string): Result<EncryptedData> {
    try {
      // Doctrine #8: Pure function heart
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.props.algorithm, Buffer.from(key, 'hex'), iv);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Handle GCM authentication tag
      let tag: string | undefined;
      if (this.props.algorithm.includes('gcm')) {
        tag = (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag().toString('hex');
      }
      
      return Result.success({
        data: encrypted,
        iv: iv.toString('hex'),
        tag,
        algorithm: this.props.algorithm
      });
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Encryption failed: ${error instanceof Error ? error.message : String(error)}`, error);
    }
  }

  /**
   * Symmetric decryption using AES (Result - complex multi-step operation)
   */
  decrypt(encrypted: EncryptedData, key: string): Result<string> {
    try {
      const decipher = createDecipheriv(
        encrypted.algorithm,
        Buffer.from(key, 'hex'),
        Buffer.from(encrypted.iv, 'hex')
      );
      
      // Handle GCM authentication tag
      if (encrypted.tag && encrypted.algorithm.includes('gcm')) {
        (decipher as unknown as { setAuthTag(tag: Buffer): void }).setAuthTag(Buffer.from(encrypted.tag, 'hex'));
      }
      
      let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return Result.success(decrypted);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Decryption failed: ${error instanceof Error ? error.message : String(error)}`, error);
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
  generateKey(size = 32): string {
    return randomBytes(size).toString('hex');
  }

  /**
   * Generate asymmetric key pair (throws on error - simple operation)
   * 
   * NOTE: For identity use cases, prefer @synet/keys which supports
   * Ed25519, secp256k1, X25519, WireGuard with format conversion
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
    }
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

  /**
   * Digital signature creation (Result - complex operation with multiple failure modes)
   * 
   * NOTE: For identity/DID use cases, prefer @synet/keys Signer unit which
   * provides algorithm-specific signing and identity-aware capabilities
   */
  sign(data: string, privateKey: string): Result<string> {
    try {
      const signer = createSign('sha256');
      signer.update(data);
      signer.end();
      
      const signature = signer.sign(privateKey, 'hex');
      return Result.success(signature);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Signing failed: ${error instanceof Error ? error.message : String(error)}`, error);
    }
  }

  /**
   * Digital signature verification (Result - complex operation with multiple failure modes)
   * 
   * NOTE: For identity/DID use cases, prefer @synet/keys Key unit which
   * provides algorithm-specific verification and can learn from Signers
   */
  verify(data: string, signature: string, publicKey: string): Result<boolean> {
    try {
      const verifier = createVerify('sha256');
      verifier.update(data);
      verifier.end();
      
      const isValid = verifier.verify(publicKey, signature, 'hex');
      return Result.success(isValid);
    } catch (error) {
      return Result.fail(`[${this.dna.id}] Verification failed: ${error instanceof Error ? error.message : String(error)}`, error);
    }
  }

  /**
   * Generate secure random bytes (throw on error - simple operation)
   */
  randomBytes(size: number): string {
    return randomBytes(size).toString('hex');
  }

  /**
   * PBKDF2 key derivation (throw on error - simple operation)
   * 
   * Password-Based Key Derivation Function 2 - industry standard
   * for deriving encryption keys from passwords with salt and iterations.
   */
  deriveKeyPBKDF2(password: string, salt: string, iterations = 100000, keyLength = 32): KeyDerivationResult {
    const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'hex') : Buffer.from(salt);
    const derivedKey = pbkdf2Sync(password, saltBuffer, iterations, keyLength, 'sha256');
    
    return {
      derivedKey: derivedKey.toString('hex'),
      salt: saltBuffer.toString('hex'),
      algorithm: 'pbkdf2',
      iterations,
      keyLength,
      timestamp: new Date()
    };
  }

  /**
   * HKDF key derivation (throw on error - simple operation)
   * 
   * HMAC-based Key Derivation Function - RFC 5869 standard
   * for deriving keys in cryptographic protocols.
   */
  deriveKeyHKDF(inputKeyMaterial: string, salt: string, info = '', keyLength = 32): KeyDerivationResult {
    // Extract phase: HMAC(salt, IKM)
    const saltBuffer = Buffer.from(salt, 'hex');
    const ikmBuffer = Buffer.from(inputKeyMaterial, 'hex');
    const prk = createHmac('sha256', saltBuffer).update(ikmBuffer).digest();
    
    // Expand phase: HMAC(PRK, info || counter)
    const infoBuffer = Buffer.from(info, 'utf8');
    const t: Buffer[] = [];
    const hashLength = 32; // SHA-256 output length
    const n = Math.ceil(keyLength / hashLength);
    
    for (let i = 1; i <= n; i++) {
      const prev = i === 1 ? Buffer.alloc(0) : t[i - 2];
      const hmac = createHmac('sha256', prk);
      hmac.update(prev);
      hmac.update(infoBuffer);
      hmac.update(Buffer.from([i]));
      t.push(hmac.digest());
    }
    
    const okm = Buffer.concat(t).subarray(0, keyLength);
    
    return {
      derivedKey: okm.toString('hex'),
      salt: saltBuffer.toString('hex'),
      algorithm: 'hkdf-sha256',
      keyLength,
      timestamp: new Date()
    };
  }

  /**
   * Scrypt key derivation (throw on error - simple operation)
   * 
   * Memory-hard key derivation function designed to be expensive
   * for attackers using custom hardware.
   */
  deriveKeyScrypt(password: string, salt: string, keyLength = 32, options: { N?: number; r?: number; p?: number } = {}): KeyDerivationResult {
    const { N = 16384, r = 8, p = 1 } = options;
    const saltBuffer = Buffer.from(salt, 'hex');
    const derivedKey = scryptSync(password, saltBuffer, keyLength, { N, r, p });
    
    return {
      derivedKey: derivedKey.toString('hex'),
      salt: saltBuffer.toString('hex'),
      algorithm: `scrypt-N${N}-r${r}-p${p}`,
      keyLength,
      timestamp: new Date()
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
