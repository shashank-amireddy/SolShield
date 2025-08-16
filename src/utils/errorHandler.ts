export class ScannerError extends Error {
  constructor(
    message: string,
    public code: string,
    public category: 'network' | 'parsing' | 'tool' | 'system' | 'validation',
    public recoverable: boolean = false,
    public context?: Record<string, any>
  ) {
    super(message);
    this.name = 'ScannerError';
  }
}

export class ErrorHandler {
  private static retryAttempts = new Map<string, number>();
  private static maxRetries = 3;

  static async withRetry<T>(
    operation: () => Promise<T>,
    operationId: string,
    maxRetries: number = this.maxRetries
  ): Promise<T> {
    const attempts = this.retryAttempts.get(operationId) || 0;
    
    try {
      const result = await operation();
      this.retryAttempts.delete(operationId); // Reset on success
      return result;
    } catch (error) {
      if (attempts >= maxRetries) {
        this.retryAttempts.delete(operationId);
        throw error;
      }

      // Check if error is retryable
      if (this.isRetryableError(error)) {
        this.retryAttempts.set(operationId, attempts + 1);
        const delay = Math.pow(2, attempts) * 1000; // Exponential backoff
        
        console.warn(`Operation ${operationId} failed (attempt ${attempts + 1}/${maxRetries}). Retrying in ${delay}ms...`);
        await this.delay(delay);
        
        return this.withRetry(operation, operationId, maxRetries);
      }

      throw error;
    }
  }

  static isRetryableError(error: any): boolean {
    if (error instanceof ScannerError) {
      return error.recoverable;
    }

    const errorMessage = error.message?.toLowerCase() || '';
    
    // Network-related errors are usually retryable
    if (errorMessage.includes('network') || 
        errorMessage.includes('timeout') || 
        errorMessage.includes('connection') ||
        errorMessage.includes('econnreset') ||
        errorMessage.includes('enotfound')) {
      return true;
    }

    // Some system errors are retryable
    if (errorMessage.includes('emfile') || 
        errorMessage.includes('enomem') ||
        errorMessage.includes('busy')) {
      return true;
    }

    return false;
  }

  static handleRepositoryError(error: any, url: string): ScannerError {
    const errorMessage = error.message?.toLowerCase() || '';

    if (errorMessage.includes('authentication') || errorMessage.includes('403')) {
      return new ScannerError(
        `Authentication failed for repository: ${url}. Please check your GitHub token and repository permissions.`,
        'AUTH_FAILED',
        'network',
        false,
        { url, originalError: error.message }
      );
    }

    if (errorMessage.includes('not found') || errorMessage.includes('404')) {
      return new ScannerError(
        `Repository not found: ${url}. Please verify the URL is correct and you have access.`,
        'REPO_NOT_FOUND',
        'network',
        false,
        { url, originalError: error.message }
      );
    }

    if (errorMessage.includes('network') || errorMessage.includes('timeout')) {
      return new ScannerError(
        `Network error while accessing repository: ${url}. Please check your internet connection.`,
        'NETWORK_ERROR',
        'network',
        true,
        { url, originalError: error.message }
      );
    }

    return new ScannerError(
      `Failed to access repository: ${error.message}`,
      'REPO_ACCESS_ERROR',
      'system',
      false,
      { url, originalError: error.message }
    );
  }

  static handleParsingError(error: any, filePath: string): ScannerError {
    return new ScannerError(
      `Failed to parse Solidity file: ${filePath}. ${error.message}`,
      'PARSING_ERROR',
      'parsing',
      false,
      { filePath, originalError: error.message }
    );
  }

  static handleToolError(error: any, toolName: string): ScannerError {
    const errorMessage = error.message?.toLowerCase() || '';

    if (errorMessage.includes('timeout') || errorMessage.includes('timed out')) {
      return new ScannerError(
        `Tool ${toolName} timed out. Consider increasing timeout or reducing analysis scope.`,
        'TOOL_TIMEOUT',
        'tool',
        true,
        { toolName, originalError: error.message }
      );
    }

    if (errorMessage.includes('not found') || errorMessage.includes('command not found')) {
      return new ScannerError(
        `Tool ${toolName} is not installed or not found in PATH. Please install the tool and try again.`,
        'TOOL_NOT_FOUND',
        'tool',
        false,
        { toolName, originalError: error.message }
      );
    }

    if (errorMessage.includes('memory') || errorMessage.includes('out of memory')) {
      return new ScannerError(
        `Tool ${toolName} ran out of memory. Try reducing the analysis scope or increasing available memory.`,
        'TOOL_MEMORY_ERROR',
        'tool',
        true,
        { toolName, originalError: error.message }
      );
    }

    return new ScannerError(
      `Tool ${toolName} failed: ${error.message}`,
      'TOOL_ERROR',
      'tool',
      false,
      { toolName, originalError: error.message }
    );
  }

  static handleSystemError(error: any): ScannerError {
    const errorMessage = error.message?.toLowerCase() || '';

    if (errorMessage.includes('enospc')) {
      return new ScannerError(
        'Insufficient disk space. Please free up disk space and try again.',
        'DISK_SPACE_ERROR',
        'system',
        false,
        { originalError: error.message }
      );
    }

    if (errorMessage.includes('emfile') || errorMessage.includes('too many open files')) {
      return new ScannerError(
        'Too many open files. The system has reached the file descriptor limit.',
        'FILE_DESCRIPTOR_LIMIT',
        'system',
        true,
        { originalError: error.message }
      );
    }

    if (errorMessage.includes('enomem')) {
      return new ScannerError(
        'Insufficient memory. Please close other applications or increase available memory.',
        'MEMORY_ERROR',
        'system',
        true,
        { originalError: error.message }
      );
    }

    return new ScannerError(
      `System error: ${error.message}`,
      'SYSTEM_ERROR',
      'system',
      false,
      { originalError: error.message }
    );
  }

  static handleValidationError(message: string, context?: Record<string, any>): ScannerError {
    return new ScannerError(
      message,
      'VALIDATION_ERROR',
      'validation',
      false,
      context
    );
  }

  static async gracefulDegradation<T>(
    operation: () => Promise<T>,
    fallback: T,
    operationName: string
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      console.warn(`Operation ${operationName} failed, using fallback: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return fallback;
    }
  }

  static formatErrorForUser(error: ScannerError): string {
    let message = `❌ ${error.message}`;
    
    if (error.code) {
      message += ` (${error.code})`;
    }

    // Add helpful suggestions based on error category
    switch (error.category) {
      case 'network':
        message += '\n💡 Tip: Check your internet connection and GitHub token permissions.';
        break;
      case 'tool':
        message += '\n💡 Tip: Ensure all security analysis tools are properly installed.';
        break;
      case 'parsing':
        message += '\n💡 Tip: Check for syntax errors in your Solidity files.';
        break;
      case 'system':
        message += '\n💡 Tip: Check system resources (disk space, memory, file descriptors).';
        break;
    }

    return message;
  }

  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export class MemoryManager {
  private static memoryThreshold = 0.9; // 90% memory usage threshold
  private static gcInterval = 60000; // Run GC every minute
  private static gcTimer?: NodeJS.Timeout;

  static startMemoryMonitoring(): void {
    this.gcTimer = setInterval(() => {
      const memUsage = process.memoryUsage();
      const heapUsedRatio = memUsage.heapUsed / memUsage.heapTotal;
      
      if (heapUsedRatio > this.memoryThreshold) {
        console.warn(`High memory usage detected: ${(heapUsedRatio * 100).toFixed(1)}%`);
        
        if (global.gc) {
          global.gc();
          console.log('Garbage collection triggered');
        }
      }
    }, this.gcInterval);
  }

  static stopMemoryMonitoring(): void {
    if (this.gcTimer) {
      clearInterval(this.gcTimer);
      this.gcTimer = undefined;
    }
  }

  static getMemoryUsage(): {
    heapUsed: number;
    heapTotal: number;
    external: number;
    rss: number;
    usagePercentage: number;
  } {
    const memUsage = process.memoryUsage();
    return {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      external: memUsage.external,
      rss: memUsage.rss,
      usagePercentage: (memUsage.heapUsed / memUsage.heapTotal) * 100
    };
  }

  static checkMemoryAvailable(requiredMB: number): boolean {
    const memUsage = process.memoryUsage();
    const availableHeap = memUsage.heapTotal - memUsage.heapUsed;
    const requiredBytes = requiredMB * 1024 * 1024;
    
    return availableHeap > requiredBytes;
  }
}