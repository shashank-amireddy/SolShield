import { BaseSecurityTool } from './base/SecurityTool';
import { ToolResult, ToolOptions, Vulnerability, VulnerabilityType } from '../types';
import { execAsync } from '../utils/process';
import * as path from 'path';
import * as fs from 'fs-extra';

interface MythrilIssue {
  swc_id: string;
  severity: string;
  contract: string;
  function: string;
  pc: number;
  title: string;
  description: string;
  debug: string;
  filename: string;
  lineno: number;
  sourceMap: string;
}

interface MythrilOutput {
  error?: string;
  issues: MythrilIssue[];
  success: boolean;
}

export class MythrilTool extends BaseSecurityTool {
  name = 'Mythril';
  version = '0.23.0';
  description = 'Symbolic execution tool for Ethereum smart contracts';

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

      console.log(`Running Mythril on ${solidityFiles.length} Solidity files...`);
      
      // Analyze each file (Mythril works better on individual files)
      const allVulnerabilities: Vulnerability[] = [];
      const allErrors: string[] = [];
      let filesAnalyzed = 0;

      for (const filePath of solidityFiles.slice(0, 5)) { // Limit to 5 files to avoid timeout
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
      
      console.log(`Mythril analysis complete. Found ${allVulnerabilities.length} potential issues across ${filesAnalyzed} files.`);
      
      return this.createToolResult(allVulnerabilities, executionTime, allErrors, {
        filesAnalyzed,
        totalFiles: solidityFiles.length
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
      const mythrilOutput: MythrilOutput = JSON.parse(rawOutput);
      
      if (!mythrilOutput.success || mythrilOutput.error) {
        return [];
      }

      return this.parseMythrilIssues(mythrilOutput.issues);
    } catch (error) {
      console.warn(`Failed to parse Mythril output: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Try direct command first
      const { stdout } = await execAsync('myth', ['version'], { timeout: 5000 });
      return stdout.includes('Mythril') || stdout.includes('myth');
    } catch (error) {
      try {
        // Try with python -m
        const { stdout } = await execAsync('python', ['-m', 'mythril', 'version'], { timeout: 5000 });
        return stdout.includes('Mythril') || stdout.includes('myth');
      } catch (error2) {
        return false;
      }
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
      'analyze',
      filePath,
      '--output-format', 'json',
      '--execution-timeout', '60', // 1 minute per file
      '--create-timeout', '10',
      '--max-depth', '12'
    ];

    // Add additional arguments if provided
    if (options?.additionalArgs) {
      args.push(...options.additionalArgs);
    }

    try {
      const { stdout, stderr } = await execAsync('myth', args, {
        timeout: options?.timeout || 120000, // 2 minutes per file
        maxBuffer: 5 * 1024 * 1024 // 5MB buffer
      });

      // Mythril sometimes outputs to stderr even on success
      const output = stdout || stderr;
      
      if (!output.trim()) {
        return [];
      }

      // Try to parse as JSON
      let mythrilOutput: MythrilOutput;
      try {
        mythrilOutput = JSON.parse(output);
      } catch (parseError) {
        // If not JSON, check if it's a simple error message
        if (output.toLowerCase().includes('error') || output.toLowerCase().includes('failed')) {
          throw new Error(`Mythril analysis failed: ${output.substring(0, 200)}`);
        }
        return [];
      }

      if (mythrilOutput.error) {
        throw new Error(mythrilOutput.error);
      }

      return this.parseMythrilIssues(mythrilOutput.issues || [], filePath);

    } catch (error) {
      if (error instanceof Error && error.message.includes('timeout')) {
        throw new Error(`Analysis timed out for ${path.basename(filePath)}`);
      }
      throw error;
    }
  }

  private parseMythrilIssues(issues: MythrilIssue[], filePath?: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const issue of issues) {
      // Skip informational issues
      if (issue.severity.toLowerCase() === 'informational') {
        continue;
      }

      const vulnerability: Vulnerability = {
        type: this.mapSwcIdToVulnerabilityType(issue.swc_id),
        severity: this.mapMythrilSeverityToSeverity(issue.severity),
        file: issue.filename || filePath || 'unknown',
        lineNumber: issue.lineno || 1,
        codeSnippet: this.extractCodeSnippet(issue),
        description: this.formatDescription(issue),
        recommendation: this.generateRecommendation(issue),
        toolSource: this.name,
        confidence: this.calculateConfidence(issue)
      };

      vulnerabilities.push(vulnerability);
    }

    return vulnerabilities;
  }

  private mapSwcIdToVulnerabilityType(swcId: string): VulnerabilityType {
    // Map SWC (Smart Contract Weakness Classification) IDs to our vulnerability types
    switch (swcId) {
      case 'SWC-107': // Reentrancy
        return VulnerabilityType.REENTRANCY;
      case 'SWC-101': // Integer Overflow and Underflow
        return VulnerabilityType.INTEGER_OVERFLOW;
      case 'SWC-104': // Unchecked Call Return Value
        return VulnerabilityType.UNCHECKED_CALL;
      case 'SWC-105': // Unprotected Ether Withdrawal
      case 'SWC-106': // Unprotected SELFDESTRUCT Instruction
        return VulnerabilityType.ACCESS_CONTROL;
      case 'SWC-116': // Block values as a proxy for time
        return VulnerabilityType.TIMESTAMP_DEPENDENCE;
      case 'SWC-113': // DoS with Failed Call
      case 'SWC-128': // DoS With Block Gas Limit
        return VulnerabilityType.DENIAL_OF_SERVICE;
      case 'SWC-114': // Transaction Order Dependence
        return VulnerabilityType.FRONT_RUNNING;
      default:
        // Default to reentrancy for unknown SWC IDs
        return VulnerabilityType.REENTRANCY;
    }
  }

  private mapMythrilSeverityToSeverity(severity: string): 'Critical' | 'High' | 'Medium' | 'Low' {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'Critical';
      case 'medium':
        return 'High';
      case 'low':
        return 'Medium';
      case 'informational':
        return 'Low';
      default:
        return 'Medium';
    }
  }

  private calculateConfidence(issue: MythrilIssue): number {
    // Mythril doesn't provide explicit confidence scores, so we estimate based on issue type
    const highConfidenceSwc = ['SWC-107', 'SWC-101', 'SWC-105', 'SWC-106'];
    const mediumConfidenceSwc = ['SWC-104', 'SWC-113', 'SWC-116'];
    
    if (highConfidenceSwc.includes(issue.swc_id)) {
      return 0.8;
    } else if (mediumConfidenceSwc.includes(issue.swc_id)) {
      return 0.6;
    } else {
      return 0.5;
    }
  }

  private extractCodeSnippet(issue: MythrilIssue): string {
    if (issue.debug && issue.debug.length > 0) {
      return issue.debug.substring(0, 100) + (issue.debug.length > 100 ? '...' : '');
    }
    
    return `Line ${issue.lineno}: ${issue.function || 'unknown function'}`;
  }

  private formatDescription(issue: MythrilIssue): string {
    let description = `[${issue.swc_id}] ${issue.title}`;
    
    if (issue.description && issue.description !== issue.title) {
      description += `: ${issue.description}`;
    }
    
    if (issue.contract) {
      description += ` (Contract: ${issue.contract})`;
    }
    
    if (issue.function) {
      description += ` (Function: ${issue.function})`;
    }
    
    return description;
  }

  private generateRecommendation(issue: MythrilIssue): string {
    switch (issue.swc_id) {
      case 'SWC-107':
        return 'Implement reentrancy guards or use the checks-effects-interactions pattern to prevent reentrancy attacks.';
      case 'SWC-101':
        return 'Use SafeMath library or upgrade to Solidity 0.8+ which has built-in overflow protection.';
      case 'SWC-104':
        return 'Always check the return value of external calls and handle failures appropriately.';
      case 'SWC-105':
      case 'SWC-106':
        return 'Implement proper access control mechanisms to restrict sensitive operations to authorized users only.';
      case 'SWC-116':
        return 'Avoid using block.timestamp or block.number for critical logic. Consider using external time oracles.';
      case 'SWC-113':
      case 'SWC-128':
        return 'Implement gas limits and avoid patterns that could lead to denial of service attacks.';
      case 'SWC-114':
        return 'Be aware of transaction ordering dependencies and consider using commit-reveal schemes where appropriate.';
      default:
        return 'Review the identified issue and implement appropriate security measures based on the vulnerability type.';
    }
  }
}