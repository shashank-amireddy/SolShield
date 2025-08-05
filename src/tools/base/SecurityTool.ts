import { SecurityTool, ToolResult, ToolOptions, Vulnerability } from '../../types';

export abstract class BaseSecurityTool implements SecurityTool {
  abstract name: string;
  abstract version: string;
  abstract description: string;

  abstract execute(repoPath: string, options?: ToolOptions): Promise<ToolResult>;
  abstract parseOutput(rawOutput: string): Vulnerability[];
  abstract isAvailable(): Promise<boolean>;

  protected createToolResult(
    vulnerabilities: Vulnerability[],
    executionTime: number,
    errors: string[] = [],
    metadata: Record<string, any> = {}
  ): ToolResult {
    return {
      toolName: this.name,
      toolVersion: this.version,
      executionTime,
      vulnerabilities,
      errors,
      metadata
    };
  }
}