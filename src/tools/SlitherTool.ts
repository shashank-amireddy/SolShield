import { BaseSecurityTool } from './base/SecurityTool';
import { ToolResult, ToolOptions, Vulnerability, VulnerabilityType } from '../types';
import { execAsync } from '../utils/process';
import * as path from 'path';

interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: SlitherElement[];
  additional_fields?: Record<string, any>;
}

interface SlitherElement {
  type: string;
  name: string;
  source_mapping: {
    start: number;
    length: number;
    filename_relative: string;
    filename_absolute: string;
    filename_short: string;
    is_dependency: boolean;
    lines: number[];
    starting_column: number;
    ending_column: number;
  };
}

interface SlitherOutput {
  success: boolean;
  error: string | null;
  results: {
    detectors: SlitherDetector[];
  };
}

export class SlitherTool extends BaseSecurityTool {
  name = 'Slither';
  version = '0.9.6';
  description = 'Fast static analysis tool for Solidity';

  async execute(repoPath: string, options?: ToolOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      // Build Slither command
      const args = [
        repoPath,
        '--json', '-', // Output JSON to stdout
        '--disable-color',
        '--exclude-dependencies' // Focus on main contracts, not dependencies
      ];

      // Add timeout if specified
      if (options?.timeout) {
        args.push('--timeout', Math.floor(options.timeout / 1000).toString());
      }

      // Add additional arguments if provided
      if (options?.additionalArgs) {
        args.push(...options.additionalArgs);
      }

      console.log(`Running Slither on ${repoPath}...`);
      const { stdout, stderr } = await execAsync('slither', args, {
        timeout: options?.timeout || 300000, // 5 minutes default
        maxBuffer: 10 * 1024 * 1024 // 10MB buffer
      });

      const executionTime = Date.now() - startTime;
      
      // Parse Slither output
      let slitherOutput: SlitherOutput;
      try {
        slitherOutput = JSON.parse(stdout);
      } catch (parseError) {
        // If JSON parsing fails, try to extract any useful information from stderr
        const errorMessage = stderr || 'Failed to parse Slither output';
        return this.createToolResult([], executionTime, [errorMessage], {
          rawOutput: stdout,
          stderr: stderr
        });
      }

      // Check if Slither execution was successful
      if (!slitherOutput.success && slitherOutput.error) {
        return this.createToolResult([], executionTime, [slitherOutput.error], {
          rawOutput: stdout,
          stderr: stderr
        });
      }

      // Parse vulnerabilities from detectors
      const vulnerabilities = this.parseSlitherDetectors(slitherOutput.results.detectors);
      
      console.log(`Slither found ${vulnerabilities.length} potential issues`);
      
      return this.createToolResult(vulnerabilities, executionTime, [], {
        detectorsRun: slitherOutput.results.detectors.length,
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
      const slitherOutput: SlitherOutput = JSON.parse(rawOutput);
      
      if (!slitherOutput.success || !slitherOutput.results) {
        return [];
      }

      return this.parseSlitherDetectors(slitherOutput.results.detectors);
    } catch (error) {
      console.warn(`Failed to parse Slither output: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Try direct command first
      const { stdout } = await execAsync('slither', ['--version'], { timeout: 5000 });
      return stdout.includes('Slither');
    } catch (error) {
      try {
        // Try with python -m
        const { stdout } = await execAsync('python', ['-m', 'slither', '--version'], { timeout: 5000 });
        return stdout.includes('Slither');
      } catch (error2) {
        return false;
      }
    }
  }

  private parseSlitherDetectors(detectors: SlitherDetector[]): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const detector of detectors) {
      // Skip low-confidence findings unless specifically requested
      if (detector.confidence === 'Low') {
        continue;
      }

      // Get the primary source location
      const primaryElement = detector.elements.find(el => el.type === 'function' || el.type === 'contract') || detector.elements[0];
      
      if (!primaryElement || !primaryElement.source_mapping) {
        continue;
      }

      const vulnerability: Vulnerability = {
        type: this.mapSlitherCheckToVulnerabilityType(detector.check),
        severity: this.mapSlitherImpactToSeverity(detector.impact),
        file: primaryElement.source_mapping.filename_relative,
        lineNumber: primaryElement.source_mapping.lines[0] || 1,
        codeSnippet: this.extractCodeSnippet(detector),
        description: this.formatDescription(detector),
        recommendation: this.generateRecommendation(detector),
        toolSource: this.name,
        confidence: this.mapSlitherConfidenceToNumber(detector.confidence)
      };

      vulnerabilities.push(vulnerability);
    }

    return vulnerabilities;
  }

  private mapSlitherCheckToVulnerabilityType(check: string): VulnerabilityType {
    const checkLower = check.toLowerCase();
    
    if (checkLower.includes('reentrancy')) {
      return VulnerabilityType.REENTRANCY;
    } else if (checkLower.includes('overflow') || checkLower.includes('underflow')) {
      return VulnerabilityType.INTEGER_OVERFLOW;
    } else if (checkLower.includes('unchecked') || checkLower.includes('call')) {
      return VulnerabilityType.UNCHECKED_CALL;
    } else if (checkLower.includes('access') || checkLower.includes('permission')) {
      return VulnerabilityType.ACCESS_CONTROL;
    } else if (checkLower.includes('timestamp') || checkLower.includes('time')) {
      return VulnerabilityType.TIMESTAMP_DEPENDENCE;
    } else if (checkLower.includes('dos') || checkLower.includes('denial')) {
      return VulnerabilityType.DENIAL_OF_SERVICE;
    } else if (checkLower.includes('front') || checkLower.includes('mev')) {
      return VulnerabilityType.FRONT_RUNNING;
    }
    
    // Default to reentrancy for unknown types
    return VulnerabilityType.REENTRANCY;
  }

  private mapSlitherImpactToSeverity(impact: string): 'Critical' | 'High' | 'Medium' | 'Low' {
    switch (impact.toLowerCase()) {
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

  private mapSlitherConfidenceToNumber(confidence: string): number {
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

  private extractCodeSnippet(detector: SlitherDetector): string {
    // Try to get code snippet from the first element with source mapping
    const elementWithCode = detector.elements.find(el => el.source_mapping && el.source_mapping.lines.length > 0);
    
    if (elementWithCode) {
      return `Line ${elementWithCode.source_mapping.lines[0]}: ${elementWithCode.name}`;
    }
    
    return detector.description.substring(0, 100) + '...';
  }

  private formatDescription(detector: SlitherDetector): string {
    let description = detector.description;
    
    // Add check type for context
    description = `[${detector.check}] ${description}`;
    
    // Add confidence and impact information
    description += ` (Impact: ${detector.impact}, Confidence: ${detector.confidence})`;
    
    return description;
  }

  private generateRecommendation(detector: SlitherDetector): string {
    const check = detector.check.toLowerCase();
    
    if (check.includes('reentrancy')) {
      return 'Use the checks-effects-interactions pattern or reentrancy guards to prevent reentrancy attacks.';
    } else if (check.includes('overflow') || check.includes('underflow')) {
      return 'Use SafeMath library or Solidity 0.8+ built-in overflow protection.';
    } else if (check.includes('unchecked-call')) {
      return 'Always check the return value of external calls and handle failures appropriately.';
    } else if (check.includes('access-control')) {
      return 'Implement proper access control mechanisms using modifiers or role-based permissions.';
    } else if (check.includes('timestamp')) {
      return 'Avoid using block.timestamp for critical logic; consider using block numbers or external oracles.';
    } else if (check.includes('dos')) {
      return 'Implement gas limits and avoid unbounded loops that could cause denial of service.';
    }
    
    return 'Review the flagged code and consider the security implications highlighted by Slither.';
  }
}