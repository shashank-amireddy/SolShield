import { BaseSecurityTool } from './base/SecurityTool';
import { ToolResult, ToolOptions, Vulnerability, VulnerabilityType } from '../types';
import { execAsync } from '../utils/process';
import * as path from 'path';
import * as fs from 'fs-extra';

interface SolhintReport {
  filePath: string;
  reports: SolhintIssue[];
  errorCount: number;
  warningCount: number;
  fixableErrorCount: number;
  fixableWarningCount: number;
}

interface SolhintIssue {
  ruleId: string;
  severity: number; // 1 = warning, 2 = error
  message: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
}

export class SolhintTool extends BaseSecurityTool {
  name = 'Solhint';
  version = '3.4.0';
  description = 'Linting and security analysis tool for Solidity';

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

      console.log(`Running Solhint on ${solidityFiles.length} Solidity files...`);
      
      // Build Solhint command
      const args = [
        '--formatter', 'json',
        '--config', await this.getConfigPath(repoPath),
        ...solidityFiles
      ];

      // Add additional arguments if provided
      if (options?.additionalArgs) {
        args.push(...options.additionalArgs);
      }

      const { stdout, stderr } = await execAsync('solhint', args, {
        timeout: options?.timeout || 120000, // 2 minutes default
        maxBuffer: 5 * 1024 * 1024 // 5MB buffer
      });

      const executionTime = Date.now() - startTime;
      
      // Parse Solhint output
      let solhintReports: SolhintReport[];
      try {
        solhintReports = JSON.parse(stdout);
      } catch (parseError) {
        // If JSON parsing fails, try to extract useful information from stderr
        const errorMessage = stderr || 'Failed to parse Solhint output';
        return this.createToolResult([], executionTime, [errorMessage], {
          rawOutput: stdout,
          stderr: stderr
        });
      }

      // Parse vulnerabilities from reports
      const vulnerabilities = this.parseSolhintReports(solhintReports);
      const errors = stderr ? [stderr] : [];
      
      console.log(`Solhint found ${vulnerabilities.length} security-related issues`);
      
      return this.createToolResult(vulnerabilities, executionTime, errors, {
        filesAnalyzed: solidityFiles.length,
        totalIssues: this.countTotalIssues(solhintReports),
        securityIssues: vulnerabilities.length,
        rawOutput: stdout
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
      const solhintReports: SolhintReport[] = JSON.parse(rawOutput);
      return this.parseSolhintReports(solhintReports);
    } catch (error) {
      console.warn(`Failed to parse Solhint output: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout } = await execAsync('solhint', ['--version'], { timeout: 5000 });
      return stdout.includes('solhint') || /\d+\.\d+\.\d+/.test(stdout);
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

  private async getConfigPath(repoPath: string): Promise<string> {
    // Look for existing Solhint config files
    const configFiles = [
      '.solhint.json',
      '.solhintrc',
      '.solhintrc.json',
      '.solhintrc.js'
    ];

    for (const configFile of configFiles) {
      const configPath = path.join(repoPath, configFile);
      if (await fs.pathExists(configPath)) {
        return configPath;
      }
    }

    // Create a default security-focused config
    const defaultConfig = {
      extends: 'solhint:recommended',
      rules: {
        // Security rules
        'avoid-call-value': 'error',
        'avoid-low-level-calls': 'warn',
        'avoid-sha3': 'warn',
        'avoid-suicide': 'error',
        'avoid-throw': 'error',
        'check-send-result': 'error',
        'compiler-version': ['error', '^0.8.0'],
        'func-visibility': ['error', { ignoreConstructors: true }],
        'mark-callable-contracts': 'warn',
        'multiple-sends': 'error',
        'no-complex-fallback': 'error',
        'no-inline-assembly': 'warn',
        'not-rely-on-block-hash': 'error',
        'not-rely-on-time': 'error',
        'reentrancy': 'error',
        'state-visibility': 'error',
        
        // Best practices
        'bracket-align': 'off',
        'code-complexity': ['error', 8],
        'function-max-lines': ['error', 50],
        'max-line-length': ['error', 120],
        'no-empty-blocks': 'error',
        'no-unused-vars': 'error',
        'quotes': ['error', 'double'],
        'semicolon': ['error', 'always']
      }
    };

    const configPath = path.join(repoPath, '.solhint.json');
    await fs.writeFile(configPath, JSON.stringify(defaultConfig, null, 2));
    return configPath;
  }

  private parseSolhintReports(reports: SolhintReport[]): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const report of reports) {
      for (const issue of report.reports) {
        // Only include security-related rules
        if (!this.isSecurityRule(issue.ruleId)) {
          continue;
        }

        const vulnerability: Vulnerability = {
          type: this.mapRuleToVulnerabilityType(issue.ruleId),
          severity: this.mapSolhintSeverityToSeverity(issue.severity),
          file: report.filePath,
          lineNumber: issue.line,
          codeSnippet: this.extractCodeSnippet(issue),
          description: this.formatDescription(issue),
          recommendation: this.generateRecommendation(issue),
          toolSource: this.name,
          confidence: this.calculateConfidence(issue)
        };

        vulnerabilities.push(vulnerability);
      }
    }

    return vulnerabilities;
  }

  private isSecurityRule(ruleId: string): boolean {
    const securityRules = new Set([
      'avoid-call-value',
      'avoid-low-level-calls',
      'avoid-sha3',
      'avoid-suicide',
      'avoid-throw',
      'check-send-result',
      'compiler-version',
      'func-visibility',
      'mark-callable-contracts',
      'multiple-sends',
      'no-complex-fallback',
      'no-inline-assembly',
      'not-rely-on-block-hash',
      'not-rely-on-time',
      'reentrancy',
      'state-visibility',
      'no-unused-vars',
      'no-empty-blocks'
    ]);

    return securityRules.has(ruleId);
  }

  private mapRuleToVulnerabilityType(ruleId: string): VulnerabilityType {
    switch (ruleId) {
      case 'reentrancy':
      case 'multiple-sends':
      case 'check-send-result':
        return VulnerabilityType.REENTRANCY;
      case 'avoid-call-value':
      case 'avoid-low-level-calls':
        return VulnerabilityType.UNCHECKED_CALL;
      case 'func-visibility':
      case 'state-visibility':
      case 'mark-callable-contracts':
        return VulnerabilityType.ACCESS_CONTROL;
      case 'not-rely-on-time':
      case 'not-rely-on-block-hash':
        return VulnerabilityType.TIMESTAMP_DEPENDENCE;
      case 'no-complex-fallback':
      case 'no-inline-assembly':
        return VulnerabilityType.DENIAL_OF_SERVICE;
      case 'avoid-suicide':
      case 'avoid-throw':
        return VulnerabilityType.ACCESS_CONTROL;
      default:
        return VulnerabilityType.ACCESS_CONTROL;
    }
  }

  private mapSolhintSeverityToSeverity(severity: number): 'Critical' | 'High' | 'Medium' | 'Low' {
    switch (severity) {
      case 2: // error
        return 'High';
      case 1: // warning
        return 'Medium';
      default:
        return 'Low';
    }
  }

  private calculateConfidence(issue: SolhintIssue): number {
    // Solhint is a linter, so confidence is generally high for rule violations
    const highConfidenceRules = [
      'reentrancy', 'avoid-call-value', 'check-send-result', 'avoid-suicide',
      'func-visibility', 'state-visibility'
    ];
    
    const mediumConfidenceRules = [
      'avoid-low-level-calls', 'not-rely-on-time', 'no-inline-assembly',
      'mark-callable-contracts'
    ];
    
    if (highConfidenceRules.includes(issue.ruleId)) {
      return 0.9;
    } else if (mediumConfidenceRules.includes(issue.ruleId)) {
      return 0.7;
    } else {
      return 0.6;
    }
  }

  private extractCodeSnippet(issue: SolhintIssue): string {
    if (issue.endLine && issue.endLine > issue.line) {
      return `Lines ${issue.line}-${issue.endLine}: ${issue.ruleId}`;
    } else {
      return `Line ${issue.line}: ${issue.ruleId}`;
    }
  }

  private formatDescription(issue: SolhintIssue): string {
    const severityText = issue.severity === 2 ? 'Error' : 'Warning';
    return `[${issue.ruleId}] ${issue.message} (${severityText})`;
  }

  private generateRecommendation(issue: SolhintIssue): string {
    switch (issue.ruleId) {
      case 'reentrancy':
        return 'Implement reentrancy guards or use the checks-effects-interactions pattern.';
      case 'avoid-call-value':
        return 'Use transfer() or send() instead of call.value() for sending Ether.';
      case 'avoid-low-level-calls':
        return 'Avoid low-level calls when possible; use high-level contract interactions.';
      case 'check-send-result':
        return 'Always check the return value of send() and handle failures appropriately.';
      case 'func-visibility':
        return 'Explicitly specify function visibility (public, external, internal, private).';
      case 'state-visibility':
        return 'Explicitly specify state variable visibility (public, internal, private).';
      case 'not-rely-on-time':
        return 'Avoid using block.timestamp for critical logic; consider alternatives.';
      case 'not-rely-on-block-hash':
        return 'Avoid using block hash for randomness; use secure randomness sources.';
      case 'avoid-suicide':
        return 'Use selfdestruct() instead of the deprecated suicide() function.';
      case 'avoid-throw':
        return 'Use revert() or require() instead of the deprecated throw statement.';
      case 'no-inline-assembly':
        return 'Avoid inline assembly unless absolutely necessary; it bypasses safety checks.';
      case 'compiler-version':
        return 'Use a recent, stable compiler version to benefit from security fixes.';
      case 'multiple-sends':
        return 'Avoid multiple external calls in a single function to prevent reentrancy.';
      case 'no-complex-fallback':
        return 'Keep fallback functions simple to avoid unexpected behavior.';
      case 'mark-callable-contracts':
        return 'Mark contracts that can be called by external contracts appropriately.';
      default:
        return 'Follow Solidity best practices and security guidelines.';
    }
  }

  private countTotalIssues(reports: SolhintReport[]): number {
    return reports.reduce((total, report) => total + report.reports.length, 0);
  }
}