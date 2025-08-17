import { SmartCheckTool } from '../tools/SmartCheckTool';
import { VulnerabilityType } from '../types';
import * as processUtils from '../utils/process';
import * as fs from 'fs-extra';

// Mock the dependencies
jest.mock('../utils/process');
jest.mock('fs-extra');

describe('SmartCheckTool', () => {
  let smartCheckTool: SmartCheckTool;
  let mockExecAsync: jest.MockedFunction<typeof processUtils.execAsync>;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
    smartCheckTool = new SmartCheckTool();
    mockExecAsync = processUtils.execAsync as jest.MockedFunction<typeof processUtils.execAsync>;
    mockFs = fs as jest.Mocked<typeof fs>;
  });

  describe('basic properties', () => {
    it('should have correct tool information', () => {
      expect(smartCheckTool.name).toBe('SmartCheck');
      expect(smartCheckTool.version).toBe('2.0.0');
      expect(smartCheckTool.description).toBe('Pattern-based analysis tool for Solidity smart contracts');
    });
  });

  describe('isAvailable', () => {
    it('should return true when SmartCheck is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'SmartCheck 2.0.0',
        stderr: ''
      });

      const result = await smartCheckTool.isAvailable();
      
      expect(result).toBe(true);
      expect(mockExecAsync).toHaveBeenCalledWith('smartcheck', ['--version'], { timeout: 5000 });
    });

    it('should return true when version contains 2.0', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '',
        stderr: 'Version 2.0'
      });

      const result = await smartCheckTool.isAvailable();
      
      expect(result).toBe(true);
    });

    it('should return false when SmartCheck is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await smartCheckTool.isAvailable();
      
      expect(result).toBe(false);
    });
  });

  describe('execute', () => {
    const mockSmartCheckOutput = {
      results: [
        {
          file: 'contracts/Test.sol',
          rules: [
            {
              patternId: 'REENTRANCY_001',
              severity: 'High',
              line: 25,
              column: 10,
              endLine: 27,
              endColumn: 15,
              message: 'Potential reentrancy vulnerability detected',
              patternName: 'reentrancy-external-call'
            }
          ]
        }
      ]
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

    it('should successfully execute and parse SmartCheck output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSmartCheckOutput),
        stderr: ''
      });

      const result = await smartCheckTool.execute('/test/repo');

      expect(result.toolName).toBe('SmartCheck');
      expect(result.toolVersion).toBe('2.0.0');
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      
      const vulnerability = result.vulnerabilities[0];
      expect(vulnerability.type).toBe(VulnerabilityType.REENTRANCY);
      expect(vulnerability.severity).toBe('Critical');
      expect(vulnerability.file).toBe('contracts/Test.sol');
      expect(vulnerability.lineNumber).toBe(25);
      expect(vulnerability.toolSource).toBe('SmartCheck');
    });

    it('should handle no Solidity files found', async () => {
      mockFs.readdir.mockResolvedValue([]);

      const result = await smartCheckTool.execute('/empty/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('No Solidity files found');
      expect(result.metadata.filesAnalyzed).toBe(0);
    });

    it('should handle SmartCheck execution errors', async () => {
      mockExecAsync.mockRejectedValue(new Error('Analysis failed'));

      const result = await smartCheckTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Analysis failed');
      expect(result.metadata.failed).toBe(true);
    });

    it('should handle JSON parsing errors', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Invalid JSON output',
        stderr: 'Some error message'
      });

      const result = await smartCheckTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Some error message');
    });

    it('should pass through options correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSmartCheckOutput),
        stderr: ''
      });

      const options = {
        timeout: 180000,
        additionalArgs: ['--exclude-patterns', 'info']
      };

      await smartCheckTool.execute('/test/repo', options);

      expect(mockExecAsync).toHaveBeenCalledWith(
        'smartcheck',
        expect.arrayContaining([
          '--output-format', 'json',
          '--rules-dir', '/opt/smartcheck/rules',
          expect.stringContaining('Contract.sol'),
          '--exclude-patterns', 'info'
        ]),
        expect.objectContaining({
          timeout: 180000
        })
      );
    });

    it('should filter out non-security-relevant informational rules', async () => {
      const outputWithInfo = {
        results: [
          {
            file: 'contracts/Test.sol',
            rules: [
              {
                patternId: 'REENTRANCY_001',
                severity: 'High',
                line: 25,
                column: 10,
                endLine: 27,
                endColumn: 15,
                message: 'Potential reentrancy vulnerability detected',
                patternName: 'reentrancy-external-call'
              },
              {
                patternId: 'STYLE_001',
                severity: 'Info',
                line: 30,
                column: 5,
                endLine: 30,
                endColumn: 20,
                message: 'Code style issue',
                patternName: 'code-style-issue' // This should be filtered out
              },
              {
                patternId: 'SECURITY_INFO',
                severity: 'Info',
                line: 35,
                column: 5,
                endLine: 35,
                endColumn: 20,
                message: 'Security-related info',
                patternName: 'unchecked-call-info' // This should be kept
              }
            ]
          }
        ]
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithInfo),
        stderr: ''
      });

      const result = await smartCheckTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(2); // High severity + security-relevant info
      expect(result.vulnerabilities[0].severity).toBe('Critical');
      expect(result.vulnerabilities[1].severity).toBe('Low');
    });

    it('should count unique rules correctly', async () => {
      const outputWithMultipleRules = {
        results: [
          {
            file: 'contracts/Test1.sol',
            rules: [
              {
                patternId: 'REENTRANCY_001',
                severity: 'High',
                line: 25,
                column: 10,
                endLine: 27,
                endColumn: 15,
                message: 'Reentrancy issue',
                patternName: 'reentrancy-external-call'
              },
              {
                patternId: 'OVERFLOW_001',
                severity: 'Medium',
                line: 30,
                column: 5,
                endLine: 30,
                endColumn: 20,
                message: 'Overflow issue',
                patternName: 'integer-overflow'
              }
            ]
          },
          {
            file: 'contracts/Test2.sol',
            rules: [
              {
                patternId: 'REENTRANCY_002',
                severity: 'High',
                line: 15,
                column: 8,
                endLine: 17,
                endColumn: 12,
                message: 'Another reentrancy issue',
                patternName: 'reentrancy-external-call' // Same pattern as first file
              }
            ]
          }
        ]
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithMultipleRules),
        stderr: ''
      });

      const result = await smartCheckTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(3);
      expect(result.metadata.rulesApplied).toBe(2); // Only 2 unique patterns
    });
  });

  describe('parseOutput', () => {
    it('should parse valid SmartCheck JSON output', () => {
      const mockOutput = {
        results: [
          {
            file: 'contracts/Math.sol',
            rules: [
              {
                patternId: 'OVERFLOW_001',
                severity: 'Medium',
                line: 15,
                column: 10,
                endLine: 15,
                endColumn: 25,
                message: 'Integer overflow detected',
                patternName: 'integer-overflow-add'
              }
            ]
          }
        ]
      };

      const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.INTEGER_OVERFLOW);
      expect(vulnerabilities[0].severity).toBe('High');
    });

    it('should handle invalid JSON gracefully', () => {
      const vulnerabilities = smartCheckTool.parseOutput('Invalid JSON');
      expect(vulnerabilities).toHaveLength(0);
    });

    it('should handle output without results', () => {
      const emptyOutput = { results: [] };
      const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(emptyOutput));
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('pattern mapping', () => {
    it('should map different patterns to correct vulnerability types', () => {
      const testCases = [
        { pattern: 'reentrancy-external-call', expected: VulnerabilityType.REENTRANCY },
        { pattern: 'integer-overflow-add', expected: VulnerabilityType.INTEGER_OVERFLOW },
        { pattern: 'unchecked-call-return', expected: VulnerabilityType.UNCHECKED_CALL },
        { pattern: 'access-control-missing', expected: VulnerabilityType.ACCESS_CONTROL },
        { pattern: 'timestamp-dependence', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { pattern: 'dos-gas-limit', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { pattern: 'front-running-order', expected: VulnerabilityType.FRONT_RUNNING }
      ];

      testCases.forEach(({ pattern, expected }) => {
        const mockOutput = {
          results: [
            {
              file: 'test.sol',
              rules: [
                {
                  patternId: 'TEST_001',
                  severity: 'High',
                  line: 1,
                  column: 1,
                  endLine: 1,
                  endColumn: 10,
                  message: `Test ${pattern}`,
                  patternName: pattern
                }
              ]
            }
          ]
        };

        const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].type).toBe(expected);
      });
    });

    it('should map SmartCheck severity levels correctly', () => {
      const testCases = [
        { severity: 'Critical', expected: 'Critical' },
        { severity: 'High', expected: 'Critical' },
        { severity: 'Medium', expected: 'High' },
        { severity: 'Warning', expected: 'High' },
        { severity: 'Low', expected: 'Medium' },
        { severity: 'Minor', expected: 'Medium' },
        { severity: 'Info', expected: 'Low' },
        { severity: 'Informational', expected: 'Low' }
      ];

      testCases.forEach(({ severity, expected }) => {
        const mockOutput = {
          results: [
            {
              file: 'test.sol',
              rules: [
                {
                  patternId: 'TEST_001',
                  severity,
                  line: 1,
                  column: 1,
                  endLine: 1,
                  endColumn: 10,
                  message: 'Test message',
                  patternName: 'test-pattern'
                }
              ]
            }
          ]
        };

        const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].severity).toBe(expected);
      });
    });
  });

  describe('confidence calculation', () => {
    it('should assign higher confidence to well-known patterns', () => {
      const highConfidencePatterns = ['reentrancy', 'unchecked-call', 'integer-overflow', 'access-control'];
      const mediumConfidencePatterns = ['timestamp-dependence', 'dos', 'gas-limit'];

      highConfidencePatterns.forEach(pattern => {
        const mockOutput = {
          results: [
            {
              file: 'test.sol',
              rules: [
                {
                  patternId: 'TEST_001',
                  severity: 'High',
                  line: 1,
                  column: 1,
                  endLine: 1,
                  endColumn: 10,
                  message: 'Test message',
                  patternName: pattern
                }
              ]
            }
          ]
        };

        const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.8);
      });

      mediumConfidencePatterns.forEach(pattern => {
        const mockOutput = {
          results: [
            {
              file: 'test.sol',
              rules: [
                {
                  patternId: 'TEST_001',
                  severity: 'High',
                  line: 1,
                  column: 1,
                  endLine: 1,
                  endColumn: 10,
                  message: 'Test message',
                  patternName: pattern
                }
              ]
            }
          ]
        };

        const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.6);
      });
    });

    it('should assign default confidence to unknown patterns', () => {
      const mockOutput = {
        results: [
          {
            file: 'test.sol',
            rules: [
              {
                patternId: 'TEST_001',
                severity: 'High',
                line: 1,
                column: 1,
                endLine: 1,
                endColumn: 10,
                message: 'Test message',
                patternName: 'unknown-pattern'
              }
            ]
          }
        ]
      };

      const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].confidence).toBe(0.5);
    });
  });

  describe('code snippet extraction', () => {
    it('should create snippet for single line', () => {
      const mockOutput = {
        results: [
          {
            file: 'test.sol',
            rules: [
              {
                patternId: 'TEST_001',
                severity: 'High',
                line: 25,
                column: 10,
                endLine: 25,
                endColumn: 20,
                message: 'Test message',
                patternName: 'test-pattern'
              }
            ]
          }
        ]
      };

      const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Line 25: test-pattern');
    });

    it('should create snippet for multiple lines', () => {
      const mockOutput = {
        results: [
          {
            file: 'test.sol',
            rules: [
              {
                patternId: 'TEST_001',
                severity: 'High',
                line: 25,
                column: 10,
                endLine: 27,
                endColumn: 20,
                message: 'Test message',
                patternName: 'test-pattern'
              }
            ]
          }
        ]
      };

      const vulnerabilities = smartCheckTool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Lines 25-27: test-pattern');
    });
  });
});