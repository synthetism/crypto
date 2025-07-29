/**
 * Result Pattern Implementation for @synet/crypto
 * 
 * Aligned with @synet/patterns for consistency across SYNET ecosystem
 * Used only for complex multi-step operations where errors are expected
 * Simple operations use throw/catch pattern for fail-fast behavior
 */

export class Result<T> {
  private constructor(
    private readonly _value?: T,
    private readonly _error?: string
  ) {}

  static success<T>(value: T): Result<T> {
    return new Result(value, undefined);
  }

  static fail<T>(error: string): Result<T> {
    return new Result<T>(undefined, error);
  }

  get isSuccess(): boolean {
    return this._error === undefined;
  }

  get isFailure(): boolean {
    return this._error !== undefined;
  }

  get value(): T {
    if (this.isFailure) {
      throw new Error(`Cannot access value of failed result: ${this._error}`);
    }
    return this._value as T;
  }

  get error(): string {
    if (this.isSuccess) {
      throw new Error('Cannot access error of successful result');
    }
    return this._error as string;
  }

  map<U>(fn: (value: T) => U): Result<U> {
    if (this.isFailure) {
      return Result.fail<U>(this._error as string);
    }
    try {
      const newValue = fn(this._value as T);
      return Result.success(newValue);
    } catch (error) {
      return Result.fail<U>(error instanceof Error ? error.message : String(error));
    }
  }

  flatMap<U>(fn: (value: T) => Result<U>): Result<U> {
    if (this.isFailure) {
      return Result.fail<U>(this._error as string);
    }
    try {
      return fn(this._value as T);
    } catch (error) {
      return Result.fail<U>(error instanceof Error ? error.message : String(error));
    }
  }
}
