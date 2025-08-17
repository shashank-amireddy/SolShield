import { SolhintTool } from '../tools/SolhintTool';
import { VulnerabilityType } from '../types';
import * as processUtils from '../utils/process';
import * as fs from 'fs-extra';

// Mock the dependencies
jest.mock('../utils/process');
jest.mock('fs-extra');

describe('SolhintTool', () => {
  let solhintTool: SolhintTool;
  let mockExecAsync: jest.MockedFunction<typeof processUtils.execAsync>;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
    solhintTool = new SolhintTool();
    mockExecAsync = processUtils.execAsync as jest.MockedFunction<typeof processUtils.execAsync>;
    mockFs = fs as jest.Mocked<typeof fs>;
  });

  describe('basic properties', () => {
    it('should have correct tool information', () => {
      expect(solhintTool.name).toBe('Solhint');
      expect(solhintTool.version).toBe('3.4.0');
      expect(solhintTool.description).toBe('Linting and security analysis tool for Solidity');
    });
  });

  describe('isAvailable', () => {
    it('should return true when Solhint is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'solhint 3.4.0',
        stderr: ''
      });

      const result = await solhintTool.isAvailable();
      
      expect(result).toBe(true);
      expect(mockExecAsync).toHaveBeenCalledWith('solhint', ['--version'], { timeout: 5000 });
    });

    it('should return true when version contains version number', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '3.4.0',
        stderr: ''
      });

      const result = await solhintTool.isAvailable();
      
      expect(result).toBe(true);
    });

    it('should return false when Solhint is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await solhintTool.isAvailable();
      
      expect(result).toBe(false);
    });
  });

  describe('execute', () => {
    const mockSolhintOutput = [
      {
        filePath: 'contracts/Test.sol',
        reports: [
          {
            ruleId: 'reentrancy',
            severity: 2, // error
            message: 'Potential reentrancy vulnerability',
            line: 25,
            column: 10,
            endLine: 27,
            endColumn: 15
          }
        ],
        errorCount: 1,
        warningCount: 0,
        fixableErrorCount: 0,
        fixableWarningCount: 0
      }
    ];

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

      // Mock config file operations
      mockFs.pathExists.mockResolvedValue(false); // No existing config
      mockFs.writeFile.mockResolvedValue(undefined);
    });

    it('should successfully execute and parse Solhint output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSolhintOutput),
        stderr: ''
      });

      const result = await solhintTool.execute('/test/repo');

      expect(result.toolName).toBe('Solhint');
      expect(result.toolVersion).toBe('3.4.0');
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      
      const vulnerability = result.vulnerabilities[0];
      expect(vulnerability.type).toBe(VulnerabilityType.REENTRANCY);
      expect(vulnerability.severity).toBe('High');
      expect(vulnerability.file).toBe('contracts/Test.sol');
      expect(vulnerability.lineNumber).toBe(25);
      expect(vulnerability.toolSource).toBe('Solhint');
    });

    it('should handle no Solidity files found', async () => {
      mockFs.readdir.mockResolvedValue([]);

      const result = await solhintTool.execute('/empty/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('No Solidity files found');
      expect(result.metadata.filesAnalyzed).toBe(0);
    });

    it('should handle Solhint execution errors', async () => {
      mockExecAsync.mockRejectedValue(new Error('Analysis failed'));

      const result = await solhintTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Analysis failed');
      expect(result.metadata.failed).toBe(true);
    });

    it('should handle JSON parsing errors', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Invalid JSON output',
        stderr: 'Some error message'
      });

      const result = await solhintTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Some error message');
    });

    it('should create default config when none exists', async () => {
      mockFs.pathExists.mockResolvedValue(false);
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSolhintOutput),
        stderr: ''
      });

      await solhintTool.execute('/test/repo');

      expect(mockFs.writeFile).toHaveBeenCalledWith(
        expect.stringContaining('.solhint.json'),
        expect.stringContaining('solhint:recommended')
      );
    });

    it('should use existing config when available', async () => {
      mockFs.pathExists
        .mockResolvedValueOnce(true) // .solhint.json exists
        .mockResolvedValue(false);
      
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSolhintOutput),
        stderr: ''
      });

      await solhintTool.execute('/test/repo');

      expect(mockFs.writeFile).not.toHaveBeenCalled();
      expect(mockExecAsync).toHaveBeenCalledWith(
        'solhint',
        expect.arrayContaining([
          '--config', expect.stringContaining('.solhint.json')
        ]),
        expect.any(Object)
      );
    });

    it('should filter out non-security rules', async () => {
      const outputWithMixedRules = [
        {
          filePath: 'contracts/Test.sol',
          reports: [
            {
              ruleId: 'reentrancy',
              severity: 2,
              message: 'Potential reentrancy vulnerability',
              line: 25,
              column: 10
            },
            {
              ruleId: 'bracket-align', // Style rule, should be filtered out
              severity: 1,
              message: 'Bracket alignment issue',
              line: 30,
              column: 5
            },
            {
              ruleId: 'func-visibility',
              severity: 2,
              message: 'Function visibility not specified',
              line: 35,
              column: 8
            }
          ],
          errorCount: 2,
          warningCount: 1,
          fixableErrorCount: 0,
          fixableWarningCount: 1
        }
      ];

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithMixedRules),
        stderr: ''
      });

      const result = await solhintTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(2); // Only security rules
      expect(result.metadata.totalIssues).toBe(3); // All issues
      expect(result.metadata.securityIssues).toBe(2); // Only security issues
    });

    it('should pass through options correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSolhintOutput),
        stderr: ''
      });

      const options = {
        timeout: 180000,
        additionalArgs: ['--max-warnings', '0']
      };

      await solhintTool.execute('/test/repo', options);

      expect(mockExecAsync).toHaveBeenCalledWith(
        'solhint',
        expect.arrayContaining([
          '--formatter', 'json',
          '--config', expect.stringContaining('.solhint.json'),
          expect.stringContaining('Contract.sol'),
          '--max-warnings', '0'
        ]),
        expect.objectContaining({
          timeout: 180000
        })
      );
    });
  });

  describe('parseOutput', () => {
    it('should parse valid Solhint JSON output', () => {
      const mockOutput = [
        {
          filePath: 'contracts/Math.sol',
          reports: [
            {
              ruleId: 'avoid-call-value',
              severity: 2,
              message: 'Avoid using call.value()',
              line: 15,
              column: 10
            }
          ],
          errorCount: 1,
          warningCount: 0,
          fixableErrorCount: 0,
          fixableWarningCount: 0
        }
      ];

      const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.UNCHECKED_CALL);
      expect(vulnerabilities[0].severity).toBe('High');
    });

    it('should handle invalid JSON gracefully', () => {
      const vulnerabilities = solhintTool.parseOutput('Invalid JSON');
      expect(vulnerabilities).toHaveLength(0);
    });

    it('should handle empty reports', () => {
      const emptyOutput = [
        {
          filePath: 'contracts/Clean.sol',
          reports: [],
          errorCount: 0,
          warningCount: 0,
          fixableErrorCount: 0,
          fixableWarningCount: 0
        }
      ];

      const vulnerabilities = solhintTool.parseOutput(JSON.stringify(emptyOutput));
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('rule mapping', () => {
    it('should map different rules to correct vulnerability types', () => {
      const testCases = [
        { rule: 'reentrancy', expected: VulnerabilityType.REENTRANCY },
        { rule: 'multiple-sends', expected: VulnerabilityType.REENTRANCY },
        { rule: 'check-send-result', expected: VulnerabilityType.REENTRANCY },
        { rule: 'avoid-call-value', expected: VulnerabilityType.UNCHECKED_CALL },
        { rule: 'avoid-low-level-calls', expected: VulnerabilityType.UNCHECKED_CALL },
        { rule: 'func-visibility', expected: VulnerabilityType.ACCESS_CONTROL },
        { rule: 'state-visibility', expected: VulnerabilityType.ACCESS_CONTROL },
        { rule: 'not-rely-on-time', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { rule: 'not-rely-on-block-hash', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { rule: 'no-complex-fallback', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { rule: 'no-inline-assembly', expected: VulnerabilityType.DENIAL_OF_SERVICE }
      ];

      testCases.forEach(({ rule, expected }) => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: rule,
                severity: 2,
                message: `Test ${rule}`,
                line: 1,
                column: 1
              }
            ],
            errorCount: 1,
            warningCount: 0,
            fixableErrorCount: 0,
            fixableWarningCount: 0
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].type).toBe(expected);
      });
    });

    it('should map Solhint severity levels correctly', () => {
      const testCases = [
        { severity: 2, expected: 'High' }, // error
        { severity: 1, expected: 'Medium' } // warning
      ];

      testCases.forEach(({ severity, expected }) => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: 'reentrancy',
                severity,
                message: 'Test message',
                line: 1,
                column: 1
              }
            ],
            errorCount: severity === 2 ? 1 : 0,
            warningCount: severity === 1 ? 1 : 0,
            fixableErrorCount: 0,
            fixableWarningCount: 0
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].severity).toBe(expected);
      });
    });
  });

  describe('confidence calculation', () => {
    it('should assign higher confidence to critical security rules', () => {
      const highConfidenceRules = ['reentrancy', 'avoid-call-value', 'check-send-result', 'func-visibility'];
      const mediumConfidenceRules = ['avoid-low-level-calls', 'not-rely-on-time', 'no-inline-assembly'];

      highConfidenceRules.forEach(rule => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: rule,
                severity: 2,
                message: 'Test message',
                line: 1,
                column: 1
              }
            ],
            errorCount: 1,
            warningCount: 0,
            fixableErrorCount: 0,
            fixableWarningCount: 0
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.9);
      });

      mediumConfidenceRules.forEach(rule => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: rule,
                severity: 2,
                message: 'Test message',
                line: 1,
                column: 1
              }
            ],
            errorCount: 1,
            warningCount: 0,
            fixableErrorCount: 0,
            fixableWarningCount: 0
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.7);
      });
    });
  });

  describe('security rule filtering', () => {
    it('should identify security-related rules correctly', () => {
      const securityRules = [
        'reentrancy', 'avoid-call-value', 'func-visibility', 'state-visibility',
        'not-rely-on-time', 'check-send-result', 'avoid-suicide'
      ];

      const styleRules = [
        'bracket-align', 'quotes', 'semicolon', 'max-line-length',
        'indent', 'no-trailing-whitespace'
      ];

      // Security rules should be included
      securityRules.forEach(rule => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: rule,
                severity: 2,
                message: 'Test message',
                line: 1,
                column: 1
              }
            ],
            errorCount: 1,
            warningCount: 0,
            fixableErrorCount: 0,
            fixableWarningCount: 0
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities).toHaveLength(1);
      });

      // Style rules should be filtered out
      styleRules.forEach(rule => {
        const mockOutput = [
          {
            filePath: 'test.sol',
            reports: [
              {
                ruleId: rule,
                severity: 1,
                message: 'Test message',
                line: 1,
                column: 1
              }
            ],
            errorCount: 0,
            warningCount: 1,
            fixableErrorCount: 0,
            fixableWarningCount: 1
          }
        ];

        const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities).toHaveLength(0);
      });
    });
  });

  describe('code snippet extraction', () => {
    it('should create snippet for single line', () => {
      const mockOutput = [
        {
          filePath: 'test.sol',
          reports: [
            {
              ruleId: 'reentrancy',
              severity: 2,
              message: 'Test message',
              line: 25,
              column: 10
            }
          ],
          errorCount: 1,
          warningCount: 0,
          fixableErrorCount: 0,
          fixableWarningCount: 0
        }
      ];

      const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Line 25: reentrancy');
    });

    it('should create snippet for multiple lines', () => {
      const mockOutput = [
        {
          filePath: 'test.sol',
          reports: [
            {
              ruleId: 'reentrancy',
              severity: 2,
              message: 'Test message',
              line: 25,
              column: 10,
              endLine: 27,
              endColumn: 15
            }
          ],
          errorCount: 1,
          warningCount: 0,
          fixableErrorCount: 0,
          fixableWarningCount: 0
        }
      ];

      const vulnerabilities = solhintTool.parseOutput(JSON.stringify(mockOutput));
      expect(vulnerabilities[0].codeSnippet).toBe('Lines 25-27: reentrancy');
    });
  });
});