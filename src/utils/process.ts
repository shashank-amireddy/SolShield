import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

export interface ExecOptions {
  timeout?: number;
  maxBuffer?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
}

export async function execAsync(command: string, args: string[] = [], options: ExecOptions = {}): Promise<ExecResult> {
  const fullCommand = `${command} ${args.map(arg => `"${arg}"`).join(' ')}`;
  
  try {
    const result = await execPromise(fullCommand, {
      timeout: options.timeout || 30000,
      maxBuffer: options.maxBuffer || 1024 * 1024, // 1MB default
      cwd: options.cwd,
      env: { ...process.env, ...options.env }
    });
    
    return {
      stdout: result.stdout,
      stderr: result.stderr
    };
  } catch (error: any) {
    // Handle timeout and other execution errors
    if (error.killed && error.signal === 'SIGTERM') {
      throw new Error(`Command timed out after ${options.timeout}ms: ${fullCommand}`);
    }
    
    // For non-zero exit codes, still return stdout/stderr if available
    if (error.stdout !== undefined || error.stderr !== undefined) {
      return {
        stdout: error.stdout || '',
        stderr: error.stderr || error.message
      };
    }
    
    throw new Error(`Command execution failed: ${error.message}`);
  }
}

export function escapeShellArg(arg: string): string {
  // Escape shell arguments to prevent injection
  return `"${arg.replace(/"/g, '\\"')}"`;
}

export function buildCommand(command: string, args: string[]): string {
  return `${command} ${args.map(escapeShellArg).join(' ')}`;
}