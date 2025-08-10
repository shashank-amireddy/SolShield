import { BaseSecurityTool } from './base/SecurityTool';
import { ToolResult, ToolOptions, Vulnerability, VulnerabilityType } from '../types';
import { execAsync } from '../utils/process';
import * as path from 'path';
import * as fs from 'fs-extra';

interface Securify2Violation {
  check: string;
  severity: string;
  confidence: string;
  file: string;
  line: number;
  column: number;
  message: string;
  description: string;
}

interface Securify2Output {
  results: Securify2Violation[];
  summary: {
    violations: number;
    warnings: number;
    safe: number;
    unknown: number;
  };
  errors?: string[];
}

export class Securify2Tool extends BaseSecurityTool {
  name = 'Securify2';
  version = '1.0.0';
  description = 'Formal verification tool for Ethereum smart contracts';

  async execute(repoPath: string, options?: ToolOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      // Find Solidity files to analyze
      const solidityFiles = await this.findSolidityFiles(repoPath);
      
      if (solidityFiles.length === 0) {
        return this.createToolResult([], Date.now() - startTime, ['No Solidity files found'], {
          filesAnalyzed: 0
        });
      }

      console.log(`Running Securify2 on ${solidityFiles.length} Solidity files...`);
      
      // Securify2 can be resource-intensive, so limit to first 3 files
      const filesToAnalyze = solidityFiles.slice(0, 3);
      const allVulnerabilities: Vulnerability[] = [];
      const allErrors: string[] = [];
      let filesAnalyzed = 0;

      for (const filePath of filesToAnalyze) {
        try {
          const fileVulnerabilities = await this.analyzeFile(filePath, options);
          allVulnerabilities.push(...fileVulnerabilities);
          filesAnalyzed++;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          allErrors.push(`Error analyzing ${path.basename(filePath)}: ${errorMessage}`);
        }
      }

      const executionTime = Date.now() - startTime;
      
      console.log(`Securify2 analysis complete. Found ${allVulnerabilities.length} potential issues across ${filesAnalyzed} files.`);
      
      return this.createToolResult(allVulnerabilities, executionTime, allErrors, {
        filesAnalyzed,
        totalFiles: solidityFiles.length,
        limitedAnalysis: solidityFiles.length > 3
      });

    } catch (error) {
      const executionTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      return this.createToolResult([], executionTime, [errorMessage], {
        failed: true,
        error: errorMessage
      });
    }
  }

  parseOutput(rawOutput: string): Vulnerability[] {
    try {
      const securify2Output: Securify2Output = JSON.parse(rawOutput);
      
      if (securify2Output.errors && securify2Output.errors.length > 0) {
        return [];
      }

      return this.parseSecurify2Violations(securify2Output.results || []);
    } catch (error) {
      console.warn(`Failed to parse Securify2 output: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout, stderr } = await execAsync('securify', ['--version'], { timeout: 10000 });
      const output = stdout || stderr;
      return output.toLowerCase().includes('securify') || output.includes('2.0') || output.includes('1.0');
    } catch (error) {
      return false;
    }
  }

  private async findSolidityFiles(repoPath: string): Promise<string[]> {
    const files: string[] = [];
    
    const traverse = async (dir: string) => {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory() && !this.shouldSkipDirectory(entry.name)) {
          await traverse(fullPath);
        } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.sol')) {
          files.push(fullPath);
        }
      }
    };
    
    await traverse(repoPath);
    return files;
  }

  private shouldSkipDirectory(dirName: string): boolean {
    const skipDirs = new Set([
      'node_modules', '.git', 'build', 'dist', 'out', 'artifacts', 'cache'
    ]);
    return skipDirs.has(dirName) || dirName.startsWith('.');
  }

  private async analyzeFile(filePath: string, options?: ToolOptions): Promise<Vulnerability[]> {
    const args = [
      '--output-format', 'json',
      '--timeout', '300', // 5 minutes per file
      filePath
    ];

    // Add additional arguments if provided
    if (options?.additionalArgs) {
      args.push(...options.additionalArgs);
    }

    try {
      const { stdout, stderr } = await execAsync('securify', args, {
        timeout: options?.timeout || 360000, // 6 minutes per file
        maxBuffer: 10 * 1024 * 1024 // 10MB buffer
      });

      // Securify2 may output to stderr even on success
      const output = stdout || stderr;
      
      if (!output.trim()) {
        return [];
      }

      // Try to parse as JSON
      let securify2Output: Securify2Output;
      try {
        securify2Output = JSON.parse(output);
      } catch (parseError) {
        // If not JSON, check if it's a simple error message
        if (output.toLowerCase().includes('error') || output.toLowerCase().includes('failed')) {
          throw new Error(`Securify2 analysis failed: ${output.substring(0, 200)}`);
        }
        return [];
      }

      if (securify2Output.errors && securify2Output.errors.length > 0) {
        throw new Error(securify2Output.errors.join('; '));
      }

      return this.parseSecurify2Violations(securify2Output.results || [], filePath);

    } catch (error) {
      if (error instanceof Error && error.message.includes('timeout')) {
        throw new Error(`Analysis timed out for ${path.basename(filePath)}`);
      }
      throw error;
    }
  }

  private parseSecurify2Violations(violations: Securify2Violation[], filePath?: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const violation of violations) {
      // Skip safe and unknown results, focus on violations and warnings
      if (violation.severity.toLowerCase() === 'safe' || violation.severity.toLowerCase() === 'unknown') {
        continue;
      }

      const vulnerability: Vulnerability = {
        type: this.mapCheckToVulnerabilityType(violation.check),
        severity: this.mapSecurify2SeverityToSeverity(violation.severity),
        file: violation.file || filePath || 'unknown',
        lineNumber: violation.line || 1,
        codeSnippet: this.extractCodeSnippet(violation),
        description: this.formatDescription(violation),
        recommendation: this.generateRecommendation(violation),
        toolSource: this.name,
        confidence: this.mapConfidenceToNumber(violation.confidence)
      };

      vulnerabilities.push(vulnerability);
    }

    return vulnerabilities;
  }

  private mapCheckToVulnerabilityType(check: string): VulnerabilityType {
    const checkLower = check.toLowerCase();
    
    if (checkLower.includes('reentrancy') || checkLower.includes('reentrant')) {
      return VulnerabilityType.REENTRANCY;
    } else if (checkLower.includes('overflow') || checkLower.includes('underflow') || checkLower.includes('integer')) {
      return VulnerabilityType.INTEGER_OVERFLOW;
    } else if (checkLower.includes('unchecked') || checkLower.includes('call') || checkLower.includes('send')) {
      return VulnerabilityType.UNCHECKED_CALL;
    } else if (checkLower.includes('access') || checkLower.includes('permission') || checkLower.includes('owner')) {
      return VulnerabilityType.ACCESS_CONTROL;
    } else if (checkLower.includes('timestamp') || checkLower.includes('time') || checkLower.includes('block')) {
      return VulnerabilityType.TIMESTAMP_DEPENDENCE;
    } else if (checkLower.includes('dos') || checkLower.includes('denial') || checkLower.includes('gas')) {
      return VulnerabilityType.DENIAL_OF_SERVICE;
    } else if (checkLower.includes('front') || checkLower.includes('order') || checkLower.includes('race')) {
      return VulnerabilityType.FRONT_RUNNING;
    }
    
    // Default to access control for unknown checks
    return VulnerabilityType.ACCESS_CONTROL;
  }

  private mapSecurify2SeverityToSeverity(severity: string): 'Critical' | 'High' | 'Medium' | 'Low' {
    switch (severity.toLowerCase()) {
      case 'violation':
      case 'critical':
        return 'Critical';
      case 'warning':
      case 'high':
        return 'High';
      case 'medium':
        return 'Medium';
      case 'low':
      case 'info':
        return 'Low';
      default:
        return 'Medium';
    }
  }

  private mapConfidenceToNumber(confidence: string): number {
    switch (confidence.toLowerCase()) {
      case 'high':
        return 0.9;
      case 'medium':
        return 0.7;
      case 'low':
        return 0.5;
      default:
        return 0.6;
    }
  }

  private extractCodeSnippet(violation: Securify2Violation): string {
    if (violation.line && violation.column) {
      return `Line ${violation.line}, Column ${violation.column}: ${violation.check}`;
    } else if (violation.line) {
      return `Line ${violation.line}: ${violation.check}`;
    } else {
      return violation.check;
    }
  }

  private formatDescription(violation: Securify2Violation): string {
    let description = `[${violation.check}] ${violation.message}`;
    
    if (violation.description && violation.description !== violation.message) {
      description += `: ${violation.description}`;
    }
    
    // Add severity and confidence information
    description += ` (Severity: ${violation.severity}, Confidence: ${violation.confidence})`;
    
    return description;
  }

  private generateRecommendation(violation: Securify2Violation): string {
    const check = violation.check.toLowerCase();
    
    if (check.includes('reentrancy')) {
      return 'Implement reentrancy guards or use the checks-effects-interactions pattern to prevent reentrancy attacks.';
    } else if (check.includes('overflow') || check.includes('underflow')) {
      return 'Use SafeMath library or upgrade to Solidity 0.8+ which has built-in overflow protection.';
    } else if (check.includes('unchecked') && check.includes('call')) {
      return 'Always check the return value of external calls and handle failures appropriately.';
    } else if (check.includes('access') || check.includes('permission')) {
      return 'Implement proper access control mechanisms using modifiers or role-based permissions.';
    } else if (check.includes('timestamp') || check.includes('time')) {
      return 'Avoid using block.timestamp for critical logic; consider using block numbers or external oracles.';
    } else if (check.includes('dos') || check.includes('gas')) {
      return 'Implement gas limits and avoid unbounded loops that could cause denial of service.';
    } else if (check.includes('front') || check.includes('order')) {
      return 'Be aware of transaction ordering dependencies and consider using commit-reveal schemes.';
    }
    
    return 'Review the flagged code and implement appropriate security measures based on the formal verification results.';
  }
}