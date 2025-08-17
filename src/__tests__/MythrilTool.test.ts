import { MythrilTool } from '../tools/MythrilTool';
import { VulnerabilityType } from '../types';
import * as processUtils from '../utils/process';
import * as fs from 'fs-extra';

// Mock the dependencies
jest.mock('../utils/process');
jest.mock('fs-extra');

describe('MythrilTool', () => {
  let mythrilTool: MythrilTool;
  let mockExecAsync: jest.MockedFunction<typeof processUtils.execAsync>;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
    mythrilTool = new MythrilTool();
    mockExecAsync = processUtils.execAsync as jest.MockedFunction<typeof processUtils.execAsync>;
    mockFs = fs as jest.Mocked<typeof fs>;
  });

  describe('basic properties', () => {
    it('should have correct tool information', () => {
      expect(mythrilTool.name).toBe('Mythril');
      expect(mythrilTool.version).toBe('0.23.0');
      expect(mythrilTool.description).toBe('Symbolic execution tool for Ethereum smart contracts');
    });
  });

  describe('isAvailable', () => {
    it('should return true when Mythril is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'Mythril 0.23.0',
        stderr: ''
      });

      const result = await mythrilTool.isAvailable();
      
      expect(result).toBe(true);
      expect(mockExecAsync).toHaveBeenCalledWith('myth', ['version'], { timeout: 5000 });
    });

    it('should return true when myth command is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'myth version 0.23.0',
        stderr: ''
      });

      const result = await mythrilTool.isAvailable();
      
      expect(result).toBe(true);
    });

    it('should return false when Mythril is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const result = await mythrilTool.isAvailable();
      
      expect(result).toBe(false);
    });
  });

  describe('execute', () => {
    const mockMythrilOutput = {
      success: true,
      issues: [
        {
          swc_id: 'SWC-107',
          severity: 'High',
          contract: 'TestContract',
          function: 'withdraw',
          pc: 100,
          title: 'Reentrancy vulnerability',
          description: 'External call in withdraw function',
          debug: 'call.value()()',
          filename: 'contracts/Test.sol',
          lineno: 25,
          sourceMap: '100:50:0'
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

    it('should successfully execute and parse Mythril output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockMythrilOutput),
        stderr: ''
      });

      const result = await mythrilTool.execute('/test/repo');

      expect(result.toolName).toBe('Mythril');
      expect(result.toolVersion).toBe('0.23.0');
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      
      const vulnerability = result.vulnerabilities[0];
      expect(vulnerability.type).toBe(VulnerabilityType.REENTRANCY);
      expect(vulnerability.severity).toBe('Critical');
      expect(vulnerability.file).toBe('contracts/Test.sol');
      expect(vulnerability.lineNumber).toBe(25);
      expect(vulnerability.toolSource).toBe('Mythril');
    });

    it('should handle no Solidity files found', async () => {
      mockFs.readdir.mockResolvedValue([]);

      const result = await mythrilTool.execute('/empty/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('No Solidity files found');
      expect(result.metadata.filesAnalyzed).toBe(0);
    });

    it('should handle Mythril execution errors', async () => {
      mockExecAsync.mockRejectedValue(new Error('Analysis failed'));

      const result = await mythrilTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.errors).toContain('Analysis failed');
      expect(result.metadata.failed).toBe(true);
    });

    it('should handle individual file analysis errors gracefully', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: JSON.stringify(mockMythrilOutput), stderr: '' })
        .mockRejectedValueOnce(new Error('File analysis failed'));

      // Mock multiple files
      mockFs.readdir.mockResolvedValue([
        { name: 'Contract1.sol', isFile: () => true, isDirectory: () => false },
        { name: 'Contract2.sol', isFile: () => true, isDirectory: () => false }
      ] as any);

      const result = await mythrilTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(1); // One file succeeded
      expect(result.errors).toHaveLength(1); // One file failed
      expect(result.metadata.filesAnalyzed).toBe(1);
    });

    it('should limit analysis to 5 files to avoid timeout', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify({ success: true, issues: [] }),
        stderr: ''
      });

      // Mock 10 files
      const mockFiles = Array.from({ length: 10 }, (_, i) => ({
        name: `Contract${i}.sol`,
        isFile: () => true,
        isDirectory: () => false
      }));
      
      mockFs.readdir.mockResolvedValue(mockFiles as any);

      const result = await mythrilTool.execute('/test/repo');

      // Should only analyze 5 files
      expect(mockExecAsync).toHaveBeenCalledTimes(5);
      expect(result.metadata.filesAnalyzed).toBe(5);
      expect(result.metadata.totalFiles).toBe(10);
    });

    it('should pass through options correctly', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(mockMythrilOutput),
        stderr: ''
      });

      const options = {
        timeout: 180000,
        additionalArgs: ['--solver-timeout', '30']
      };

      await mythrilTool.execute('/test/repo', options);

      expect(mockExecAsync).toHaveBeenCalledWith(
        'myth',
        expect.arrayContaining([
          'analyze',
          expect.stringContaining('Contract.sol'),
          '--output-format', 'json',
          '--execution-timeout', '60',
          '--create-timeout', '10',
          '--max-depth', '12',
          '--solver-timeout', '30'
        ]),
        expect.objectContaining({
          timeout: 180000
        })
      );
    });

    it('should filter out informational issues', async () => {
      const outputWithInformational = {
        success: true,
        issues: [
          {
            swc_id: 'SWC-107',
            severity: 'High',
            contract: 'TestContract',
            function: 'withdraw',
            pc: 100,
            title: 'Reentrancy vulnerability',
            description: 'External call in withdraw function',
            debug: 'call.value()()',
            filename: 'contracts/Test.sol',
            lineno: 25,
            sourceMap: '100:50:0'
          },
          {
            swc_id: 'SWC-103',
            severity: 'Informational', // This should be filtered out
            contract: 'TestContract',
            function: 'info',
            pc: 200,
            title: 'Informational issue',
            description: 'Just for information',
            debug: 'info',
            filename: 'contracts/Test.sol',
            lineno: 30,
            sourceMap: '200:20:0'
          }
        ]
      };

      mockExecAsync.mockResolvedValue({
        stdout: JSON.stringify(outputWithInformational),
        stderr: ''
      });

      const result = await mythrilTool.execute('/test/repo');

      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].severity).toBe('Critical');
    });
  });

  describe('parseOutput', () => {
    it('should parse valid Mythril JSON output', () => {
      const mockOutput = {
        success: true,
        issues: [
          {
            swc_id: 'SWC-101',
            severity: 'Medium',
            contract: 'MathContract',
            function: 'add',
            pc: 50,
            title: 'Integer overflow',
            description: 'Arithmetic operation overflow',
            debug: 'a + b',
            filename: 'contracts/Math.sol',
            lineno: 10,
            sourceMap: '50:20:0'
          }
        ]
      };

      const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(mockOutput));

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.INTEGER_OVERFLOW);
      expect(vulnerabilities[0].severity).toBe('High');
    });

    it('should handle invalid JSON gracefully', () => {
      const vulnerabilities = mythrilTool.parseOutput('Invalid JSON');
      expect(vulnerabilities).toHaveLength(0);
    });

    it('should handle unsuccessful Mythril output', () => {
      const failedOutput = {
        success: false,
        error: 'Analysis failed',
        issues: []
      };

      const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(failedOutput));
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('SWC ID mapping', () => {
    it('should map different SWC IDs to correct vulnerability types', () => {
      const testCases = [
        { swcId: 'SWC-107', expected: VulnerabilityType.REENTRANCY },
        { swcId: 'SWC-101', expected: VulnerabilityType.INTEGER_OVERFLOW },
        { swcId: 'SWC-104', expected: VulnerabilityType.UNCHECKED_CALL },
        { swcId: 'SWC-105', expected: VulnerabilityType.ACCESS_CONTROL },
        { swcId: 'SWC-106', expected: VulnerabilityType.ACCESS_CONTROL },
        { swcId: 'SWC-116', expected: VulnerabilityType.TIMESTAMP_DEPENDENCE },
        { swcId: 'SWC-113', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { swcId: 'SWC-128', expected: VulnerabilityType.DENIAL_OF_SERVICE },
        { swcId: 'SWC-114', expected: VulnerabilityType.FRONT_RUNNING }
      ];

      testCases.forEach(({ swcId, expected }) => {
        const mockOutput = {
          success: true,
          issues: [
            {
              swc_id: swcId,
              severity: 'High',
              contract: 'TestContract',
              function: 'test',
              pc: 100,
              title: `Test ${swcId}`,
              description: 'Test description',
              debug: 'test debug',
              filename: 'test.sol',
              lineno: 1,
              sourceMap: '0:10:0'
            }
          ]
        };

        const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].type).toBe(expected);
      });
    });

    it('should map Mythril severity levels correctly', () => {
      const testCases = [
        { severity: 'High', expected: 'Critical' },
        { severity: 'Medium', expected: 'High' },
        { severity: 'Low', expected: 'Medium' },
        { severity: 'Informational', expected: 'Low' }
      ];

      testCases.forEach(({ severity, expected }) => {
        const mockOutput = {
          success: true,
          issues: [
            {
              swc_id: 'SWC-107',
              severity,
              contract: 'TestContract',
              function: 'test',
              pc: 100,
              title: 'Test issue',
              description: 'Test description',
              debug: 'test debug',
              filename: 'test.sol',
              lineno: 1,
              sourceMap: '0:10:0'
            }
          ]
        };

        const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].severity).toBe(expected);
      });
    });
  });

  describe('confidence calculation', () => {
    it('should assign higher confidence to well-known vulnerability types', () => {
      const highConfidenceSwc = ['SWC-107', 'SWC-101', 'SWC-105', 'SWC-106'];
      const mediumConfidenceSwc = ['SWC-104', 'SWC-113', 'SWC-116'];

      highConfidenceSwc.forEach(swcId => {
        const mockOutput = {
          success: true,
          issues: [
            {
              swc_id: swcId,
              severity: 'High',
              contract: 'TestContract',
              function: 'test',
              pc: 100,
              title: 'Test issue',
              description: 'Test description',
              debug: 'test debug',
              filename: 'test.sol',
              lineno: 1,
              sourceMap: '0:10:0'
            }
          ]
        };

        const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.8);
      });

      mediumConfidenceSwc.forEach(swcId => {
        const mockOutput = {
          success: true,
          issues: [
            {
              swc_id: swcId,
              severity: 'High',
              contract: 'TestContract',
              function: 'test',
              pc: 100,
              title: 'Test issue',
              description: 'Test description',
              debug: 'test debug',
              filename: 'test.sol',
              lineno: 1,
              sourceMap: '0:10:0'
            }
          ]
        };

        const vulnerabilities = mythrilTool.parseOutput(JSON.stringify(mockOutput));
        expect(vulnerabilities[0].confidence).toBe(0.6);
      });
    });
  });
});