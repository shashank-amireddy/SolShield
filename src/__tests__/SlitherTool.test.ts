import { SlitherTool } from '../tools/SlitherTool';
import { VulnerabilityType } from '../types';
import * as processUtils from '../utils/process';

// Mock the process utils
jest.mock('../utils/process');

describe('SlitherTool', () => {
  let slitherTool: SlitherTool;
  let mockExecAsync: jest.MockedFunction<typeof processUtils.execAsync>;

  beforeEach(() => {
    jest.clearAllMocks();
    slitherTool = new SlitherTool();
    mockExecAsync = processUtils.execAsync as jest.MockedFunction<typeof processUtils.execAsync>;
  });

  describe('basic properties', () => {
    it('should have correct tool information', () => {
      expect(slitherTool.name).toBe('Slither');
      expect(slitherTool.version).toBe('0.9.6');
      expect(slitherTool.description).toBe('Fast static analysis tool for Solidity');
    });
  });

  describe('isAvailable', () => {
    it('should return true when Slither is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Slither 0.9.6',
        stderr: ''
      });

      const result = await slitherTool.isAvailable();
      
      expect(result).toBe(true);
      expect(mockExecAsync).toHaveBeenCalledWith('slither', ['--version'], { timeout: 5000 });
    });

    it('should return false when Slither is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await slitherTool.isAvailable();
      
      expect(result).toBe(false);
    });

    it('should return false when version output does not contain Slither', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Some other tool',
        stderr: ''
      });

      const result = await slitherTool.isAvailable();
      
      expect(result).toBe(false);
    });
  });

  describe('execute', () => {
    const mockSlitherOutput = {
      success: true,
      error: null,
      results: {
        detectors: [
          {
            check: 'reentrancy-eth',
            impact: 'High',
            confidence: 'Medium',
            description: 'Reentrancy in Contract.withdraw()',
            elements: [
              {
                type: 'function',
                name: 'withdraw',
                source_mapping: {
                  start: 100,
                  length: 50,
                  filename_relative: 'contracts/Contract.sol',
                  filename_absolute: '/path/to/contracts/Contract.sol',
                  filename_short: 'Contract.sol',
                  is_dependency: false,
                  lines: [10, 11, 12],
                  starting_column: 5,
                  ending_column: 10
                }
              }
            ]
          }
        ]
      }
    };

    it('should successfully execute and parse Slither output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSlitherOutput),
        stderr: ''
      });

      const result = await slitherTool.execute('/test/repo');

      expect(result.toolName).toBe('Slither');
      expect(result.toolVersion).toBe('0.9.6');
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      
      const vulnerability = result.vulnerabilities[0];
      expect(vulnerability.type).toBe(VulnerabilityType.REENTRANCY);
      expect(vulnerability.severity).toBe('Critical');
      expect(vulnerability.file).toBe('contracts/Contract.sol');
      expect(vulnerability.lineNumber).toBe(10);
      expect(vulnerability.toolSource).toBe('Slither');
    });

    it('should handle Slither execution errors', async () => {
      const errorOutput = {
        success: false,
        error: 'Compilation failed',
        results: { detectors: [] }
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(errorOutput),
        stderr: ''
      });

      const result = await slitherTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Compilation failed');
    });

    it('should handle JSON parsing errors', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Invalid JSON output',
        stderr: 'Some error message'
      });

      const result = await slitherTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Some error message');
    });

    it('should handle command execution failures', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await slitherTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Command not found');
      expect(result.metadata.failed).toBe(true);
    });

    it('should pass through options correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockSlitherOutput),
        stderr: ''
      });

      const options = {
        timeout: 60000,
        additionalArgs: ['--exclude-low']
      };

      await slitherTool.execute('/test/repo', options);

      expect(mockExecAsync).toHaveBeenCalledWith(
        'slither',
        expect.arrayContaining([
          '/test/repo',
          '--json', '-',
          '--disable-color',
          '--exclude-dependencies',
          '--timeout', '60',
          '--exclude-low'
        ]),
        expect.objectContaining({
          timeout: 60000
        })
      );
    });

    it('should filter out low confidence findings', async () => {
      const outputWithLowConfidence = {
        success: true,
        error: null,
        results: {
          detectors: [
            {
              check: 'reentrancy-eth',
              impact: 'High',
              confidence: 'Low', // This should be filtered out
              description: 'Low confidence reentrancy',
              elements: [
                {
                  type: 'function',
                  name: 'withdraw',
                  source_mapping: {
                    start: 100,
                    length: 50,
                    filename_relative: 'contracts/Contract.sol',
                    filename_absolute: '/path/to/contracts/Contract.sol',
                    filename_short: 'Contract.sol',
                    is_dependency: false,
                    lines: [10],
                    starting_column: 5,
                    ending_column: 10
                  }
                }
              ]
            },
            {
              check: 'unchecked-call',
              impact: 'Medium',
              confidence: 'High',
              description: 'Unchecked call',
              elements: [
                {
                  type: 'function',
                  name: 'call',
                  source_mapping: {
                    start: 200,
                    length: 30,
                    filename_relative: 'contracts/Contract.sol',
                    filename_absolute: '/path/to/contracts/Contract.sol',
                    filename_short: 'Contract.sol',
                    is_dependency: false,
                    lines: [20],
                    starting_column: 5,
                    ending_column: 10
                  }
                }
              ]
            }
          ]
        }
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithLowConfidence),
        stderr: ''
      });

      const result = await slitherTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].type).toBe(VulnerabilityType.UNCHECKED_CALL);
    });
  });

  describe('parseOutput', () => {
    it('should parse valid Slither JSON output', () => {
      const mockOutput = {
        success: true,
        error: null,
        results: {
          detectors: [
            {
              check: 'integer-overflow',
              impact: 'High',
              confidence: 'High',
              description: 'Integer overflow in calculation',
              elements: [
                {
                  type: 'function',
                  name: 'calculate',
                  source_mapping: {
                    start: 150,
                    length: 40,
                    filename_relative: 'contracts/Math.sol',
                    filename_absolute: '/path/to/contracts/Math.sol',
                    filename_short: 'Math.sol',
                    is_dependency: false,
                    lines: [15],
                    starting_column: 5,
                    ending_column: 10
                  }
                }
              ]
            }
          ]
        }
      };

      const vulnerabilities = slitherTool.parseOutput(JSON.stringify(mockOutput));

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.INTEGER_OVERFLOW);
      expect(vulnerabilities[0].severity).toBe('Critical');
    });

    it('should handle invalid JSON gracefully', () => {
      const vulnerabilities = slitherTool.parseOutput('Invalid JSON');
      expect(vulnerabilities).toHaveLength(0);
    });

    it('should handle unsuccessful Slither output', () => {
      const failedOutput = {
        success: false,
        error: 'Analysis failed',
        results: null
      };

      const vulnerabilities = slitherTool.parseOutput(JSON.stringify(failedOutput));
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('vulnerability mapping', () => {
    it('should map different Slither checks to correct vulnerability types', () => {
      const testCases = [
        { check: 'reentrancy-eth', expected: VulnerabilityType.REENTRANCY },
        { check: 'integer-overflow', expected: VulnerabilityType.INTEGER_OVERFLOW },
        { check: 'unchecked-call', expected: VulnerabilityType.UNCHECKED_CALL },
        { check: 'access-control', expected: VulnerabilityType.ACCESS_CONTROL },
        { check: 'timestamp-dependence', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { check: 'dos-gas-limit', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { check: 'front-running', expected: VulnerabilityType.FRONT_RUNNING }
      ];

      testCases.forEach(({ check, expected }) => {
        const mockOutput = {
          success: true,
          error: null,
          results: {
            detectors: [
              {
                check,
                impact: 'High',
                confidence: 'High',
                description: `Test ${check}`,
                elements: [
                  {
                    type: 'function',
                    name: 'test',
                    source_mapping: {
                      start: 0,
                      length: 10,
                      filename_relative: 'test.sol',
                      filename_absolute: '/test.sol',
                      filename_short: 'test.sol',
                      is_dependency: false,
                      lines: [1],
                      starting_column: 1,
                      ending_column: 10
                    }
                  }
                ]
              }
            ]
          }
        };

        const vulnerabilities = slitherTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].type).toBe(expected);
      });
    });

    it('should map Slither impact levels to severity correctly', () => {
      const testCases = [
        { impact: 'High', expected: 'Critical' },
        { impact: 'Medium', expected: 'High' },
        { impact: 'Low', expected: 'Medium' },
        { impact: 'Informational', expected: 'Low' }
      ];

      testCases.forEach(({ impact, expected }) => {
        const mockOutput = {
          success: true,
          error: null,
          results: {
            detectors: [
              {
                check: 'test-check',
                impact,
                confidence: 'High',
                description: 'Test description',
                elements: [
                  {
                    type: 'function',
                    name: 'test',
                    source_mapping: {
                      start: 0,
                      length: 10,
                      filename_relative: 'test.sol',
                      filename_absolute: '/test.sol',
                      filename_short: 'test.sol',
                      is_dependency: false,
                      lines: [1],
                      starting_column: 1,
                      ending_column: 10
                    }
                  }
                ]
              }
            ]
          }
        };

        const vulnerabilities = slitherTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].severity).toBe(expected);
      });
    });
  });
});