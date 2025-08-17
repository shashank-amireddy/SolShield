import { Securify2Tool } from '../tools/Securify2Tool';
import { VulnerabilityType } from '../types';
import * as processUtils from '../utils/process';
import * as fs from 'fs-extra';

// Mock the dependencies
jest.mock('../utils/process');
jest.mock('fs-extra');

describe('Securify2Tool', () => {
  let securify2Tool: Securify2Tool;
  let mockExecAsync: jest.MockedFunction<typeof processUtils.execAsync>;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
    securify2Tool = new Securify2Tool();
    mockExecAsync = processUtils.execAsync as jest.MockedFunction<typeof processUtils.execAsync>;
    mockFs = fs as jest.Mocked<typeof fs>;
  });

  describe('basic properties', () => {
    it('should have correct tool information', () => {
      expect(securify2Tool.name).toBe('Securify2');
      expect(securify2Tool.version).toBe('1.0.0');
      expect(securify2Tool.description).toBe('Formal verification tool for Ethereum smart contracts');
    });
  });

  describe('isAvailable', () => {
    it('should return true when Securify2 is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Securify 2.0',
        stderr: ''
      });

      const result = await securify2Tool.isAvailable();
      
      expect(result).toBe(true);
      expect(mockExecAsync).toHaveBeenCalledWith('securify', ['--version'], { timeout: 10000 });
    });

    it('should return true when version contains securify', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '',
        stderr: 'securify version 1.0'
      });

      const result = await securify2Tool.isAvailable();
      
      expect(result).toBe(true);
    });

    it('should return false when Securify2 is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await securify2Tool.isAvailable();
      
      expect(result).toBe(false);
    });
  });

  describe('execute', () => {
    const mockSecurify2Output = {
      results: [
        {
          check: 'reentrancy-vulnerability',
          severity: 'violation',
          confidence: 'high',
          file: 'contracts/Test.sol',
          line: 25,
          column: 10,
          message: 'Potential reentrancy vulnerability detected',
          description: 'External call followed by state change'
        }
      ],
      summary: {
        violations: 1,
        warnings: 0,
        safe: 0,
        unknown: 0
      }
    };

    beforeEach(() => {
      // Mock file system operations
      mockFs.readdir.mockImplementation((dirPath: string) => {
        if (typeof dirPath === 'string' && dirPath.includes('test-repo')) {
          return Promise.resolve([
            { name: 'Contract.sol', isFile: () => true, isDirectory: () => false }
          ] as any);
        }
        return Promise.resolve([]);
      });
    });

    it('should successfully execute and parse Securify2 output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSecurify2Output),
        stderr: ''
      });

      const result = await securify2Tool.execute('/test/repo');

      expect(result.toolName).toBe('Securify2');
      expect(result.toolVersion).toBe('1.0.0');
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      
      const vulnerability = result.vulnerabilities[0];
      expect(vulnerability.type).toBe(VulnerabilityType.REENTRANCY);
      expect(vulnerability.severity).toBe('Critical');
      expect(vulnerability.file).toBe('contracts/Test.sol');
      expect(vulnerability.lineNumber).toBe(25);
      expect(vulnerability.toolSource).toBe('Securify2');
    });

    it('should handle no Solidity files found', async () => {
      mockFs.readdir.mockResolvedValue([]);

      const result = await securify2Tool.execute('/empty/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('No Solidity files found');
      expect(result.metadata.filesAnalyzed).toBe(0);
    });

    it('should handle Securify2 execution errors', async () => {
      mockExecAsync.mockRejectedValue(new Error('Analysis failed'));

      const result = await securify2Tool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Analysis failed');
      expect(result.metadata.failed).toBe(true);
    });

    it('should handle individual file analysis errors gracefully', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: JSON.stringify(mockSecurify2Output), stderr: '' })
        .mockRejectedValueOnce(new Error('File analysis failed'));

      // Mock multiple files
      mockFs.readdir.mockResolvedValue([
        { name: 'Contract1.sol', isFile: () => true, isDirectory: () => false },
        { name: 'Contract2.sol', isFile: () => true, isDirectory: () => false }
      ] as any);

      const result = await securify2Tool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(1); // One file succeeded
      expect(result.errors).toHaveLength(1); // One file failed
      expect(result.metadata.filesAnalyzed).toBe(1);
    });

    it('should limit analysis to 3 files to avoid timeout', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify({ results: [], summary: { violations: 0, warnings: 0, safe: 1, unknown: 0 } }),
        stderr: ''
      });

      // Mock 5 files
      const mockFiles = Array.from({ length: 5 }, (_, i) => ({
        name: `Contract${i}.sol`,
        isFile: () => true,
        isDirectory: () => false
      }));
      
      mockFs.readdir.mockResolvedValue(mockFiles as any);

      const result = await securify2Tool.execute('/test/repo');

      // Should only analyze 3 files
      expect(mockExecAsync).toHaveBeenCalledTimes(3);
      expect(result.metadata.filesAnalyzed).toBe(3);
      expect(result.metadata.totalFiles).toBe(5);
      expect(result.metadata.limitedAnalysis).toBe(true);
    });

    it('should pass through options correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSecurify2Output),
        stderr: ''
      });

      const options = {
        timeout: 600000,
        additionalArgs: ['--verbose']
      };

      await securify2Tool.execute('/test/repo', options);

      expect(mockExecAsync).toHaveBeenCalledWith(
        'securify',
        expect.arrayContaining([
          '--output-format', 'json',
          '--timeout', '300',
          expect.stringContaining('Contract.sol'),
          '--verbose'
        ]),
        expect.objectContaining({
          timeout: 600000
        })
      );
    });

    it('should filter out safe and unknown results', async () => {
      const outputWithMixedResults = {
        results: [
          {
            check: 'reentrancy-vulnerability',
            severity: 'violation',
            confidence: 'high',
            file: 'contracts/Test.sol',
            line: 25,
            column: 10,
            message: 'Reentrancy vulnerability',
            description: 'External call followed by state change'
          },
          {
            check: 'safe-pattern',
            severity: 'safe', // This should be filtered out
            confidence: 'high',
            file: 'contracts/Test.sol',
            line: 30,
            column: 5,
            message: 'Safe pattern detected',
            description: 'No issues found'
          },
          {
            check: 'unknown-pattern',
            severity: 'unknown', // This should be filtered out
            confidence: 'medium',
            file: 'contracts/Test.sol',
            line: 35,
            column: 8,
            message: 'Unknown pattern',
            description: 'Cannot determine safety'
          },
          {
            check: 'access-control-issue',
            severity: 'warning',
            confidence: 'medium',
            file: 'contracts/Test.sol',
            line: 40,
            column: 12,
            message: 'Access control warning',
            description: 'Potential access control issue'
          }
        ],
        summary: {
          violations: 1,
          warnings: 1,
          safe: 1,
          unknown: 1
        }
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithMixedResults),
        stderr: ''
      });

      const result = await securify2Tool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(2); // Only violation and warning
      expect(result.vulnerabilities[0].severity).toBe('Critical');
      expect(result.vulnerabilities[1].severity).toBe('High');
    });

    it('should handle output with errors', async () => {
      const outputWithErrors = {
        results: [],
        summary: {
          violations: 0,
          warnings: 0,
          safe: 0,
          unknown: 0
        },
        errors: ['Compilation failed', 'Invalid syntax']
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithErrors),
        stderr: ''
      });

      const result = await securify2Tool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Error analyzing Contract.sol: Compilation failed; Invalid syntax');
    });
  });

  describe('parseOutput', () => {
    it('should parse valid Securify2 JSON output', () => {
      const mockOutput = {
        results: [
          {
            check: 'integer-overflow',
            severity: 'violation',
            confidence: 'high',
            file: 'contracts/Math.sol',
            line: 15,
            column: 10,
            message: 'Integer overflow detected',
            description: 'Arithmetic operation may overflow'
          }
        ],
        summary: {
          violations: 1,
          warnings: 0,
          safe: 0,
          unknown: 0
        }
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.INTEGER_OVERFLOW);
      expect(vulnerabilities[0].severity).toBe('Critical');
    });

    it('should handle invalid JSON gracefully', () => {
      const vulnerabilities = securify2Tool.parseOutput('Invalid JSON');
      expect(vulnerabilities).toHaveLength(0);
    });

    it('should handle output with errors', () => {
      const outputWithErrors = {
        results: [],
        summary: { violations: 0, warnings: 0, safe: 0, unknown: 0 },
        errors: ['Analysis failed']
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(outputWithErrors));
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('check mapping', () => {
    it('should map different checks to correct vulnerability types', () => {
      const testCases = [
        { check: 'reentrancy-vulnerability', expected: VulnerabilityType.REENTRANCY },
        { check: 'integer-overflow-check', expected: VulnerabilityType.INTEGER_OVERFLOW },
        { check: 'unchecked-call-return', expected: VulnerabilityType.UNCHECKED_CALL },
        { check: 'access-control-missing', expected: VulnerabilityType.ACCESS_CONTROL },
        { check: 'timestamp-dependence', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { check: 'dos-gas-limit', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { check: 'front-running-order', expected: VulnerabilityType.FRONT_RUNNING }
      ];

      testCases.forEach(({ check, expected }) => {
        const mockOutput = {
          results: [
            {
              check,
              severity: 'violation',
              confidence: 'high',
              file: 'test.sol',
              line: 1,
              column: 1,
              message: `Test ${check}`,
              description: 'Test description'
            }
          ],
          summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
        };

        const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].type).toBe(expected);
      });
    });

    it('should map Securify2 severity levels correctly', () => {
      const testCases = [
        { severity: 'violation', expected: 'Critical' },
        { severity: 'critical', expected: 'Critical' },
        { severity: 'warning', expected: 'High' },
        { severity: 'high', expected: 'High' },
        { severity: 'medium', expected: 'Medium' },
        { severity: 'low', expected: 'Low' },
        { severity: 'info', expected: 'Low' }
      ];

      testCases.forEach(({ severity, expected }) => {
        const mockOutput = {
          results: [
            {
              check: 'test-check',
              severity,
              confidence: 'high',
              file: 'test.sol',
              line: 1,
              column: 1,
              message: 'Test message',
              description: 'Test description'
            }
          ],
          summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
        };

        const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].severity).toBe(expected);
      });
    });
  });

  describe('confidence mapping', () => {
    it('should map confidence levels correctly', () => {
      const testCases = [
        { confidence: 'high', expected: 0.9 },
        { confidence: 'medium', expected: 0.7 },
        { confidence: 'low', expected: 0.5 }
      ];

      testCases.forEach(({ confidence, expected }) => {
        const mockOutput = {
          results: [
            {
              check: 'test-check',
              severity: 'violation',
              confidence,
              file: 'test.sol',
              line: 1,
              column: 1,
              message: 'Test message',
              description: 'Test description'
            }
          ],
          summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
        };

        const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(expected);
      });
    });

    it('should assign default confidence to unknown levels', () => {
      const mockOutput = {
        results: [
          {
            check: 'test-check',
            severity: 'violation',
            confidence: 'unknown',
            file: 'test.sol',
            line: 1,
            column: 1,
            message: 'Test message',
            description: 'Test description'
          }
        ],
        summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].confidence).toBe(0.6);
    });
  });

  describe('code snippet extraction', () => {
    it('should create snippet with line and column', () => {
      const mockOutput = {
        results: [
          {
            check: 'test-check',
            severity: 'violation',
            confidence: 'high',
            file: 'test.sol',
            line: 25,
            column: 10,
            message: 'Test message',
            description: 'Test description'
          }
        ],
        summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Line 25, Column 10: test-check');
    });

    it('should create snippet with line only', () => {
      const mockOutput = {
        results: [
          {
            check: 'test-check',
            severity: 'violation',
            confidence: 'high',
            file: 'test.sol',
            line: 25,
            column: 0,
            message: 'Test message',
            description: 'Test description'
          }
        ],
        summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Line 25: test-check');
    });

    it('should create snippet with check name only when no location', () => {
      const mockOutput = {
        results: [
          {
            check: 'test-check',
            severity: 'violation',
            confidence: 'high',
            file: 'test.sol',
            line: 0,
            column: 0,
            message: 'Test message',
            description: 'Test description'
          }
        ],
        summary: { violations: 1, warnings: 0, safe: 0, unknown: 0 }
      };

      const vulnerabilities = securify2Tool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('test-check');
    });
  });
});