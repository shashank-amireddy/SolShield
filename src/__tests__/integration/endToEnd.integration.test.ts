import { GitHubRepositoryManager } from '../../core/RepositoryManager';
import { SecurityToolRunner } from '../../core/MultiToolRunner';
import { VulnerabilityReportAggregator } from '../../core/ReportAggregator';
import { ToolRegistry } from '../../core/ToolRegistry';
import { AnalysisDashboard } from '../../core/AnalysisDashboard';
import { VulnerabilityNormalizer } from '../../core/VulnerabilityNormalizer';
import { VulnerabilityDeduplicator } from '../../core/VulnerabilityDeduplicator';
import { CrossToolAnalyzer } from '../../core/CrossToolAnalyzer';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';

describe('End-to-End Integration Tests', () => {
  let testRepoPath: string;
  let repositoryManager: GitHubRepositoryManager;
  let toolRunner: SecurityToolRunner;
  let reportAggregator: VulnerabilityReportAggregator;

  beforeAll(async () => {
    // Create test repository with vulnerable contracts
    testRepoPath = path.join(os.tmpdir(), 'test-vulnerable-contracts');
    await fs.ensureDir(testRepoPath);
    
    await createTestContracts(testRepoPath);
    
    repositoryManager = new GitHubRepositoryManager();
    toolRunner = new SecurityToolRunner();
    reportAggregator = new VulnerabilityReportAggregator();
  });

  afterAll(async () => {
    if (await fs.pathExists(testRepoPath)) {
      await fs.remove(testRepoPath);
    }
  });

  describe('Complete Analysis Workflow', () => {
    it('should perform complete vulnerability analysis workflow', async () => {
      // Step 1: Discover Solidity files
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);
      expect(solidityFiles.length).toBeGreaterThan(0);

      // Step 2: Register mock tools (since real tools may not be available in test environment)
      const mockTool = createMockSecurityTool();
      toolRunner.registerTool(mockTool);

      // Step 3: Run analysis
      const toolResults = await toolRunner.runAllTools(testRepoPath);
      expect(toolResults).toHaveLength(1);
      expect(toolResults[0].vulnerabilities.length).toBeGreaterThan(0);

      // Step 4: Generate report
      const toolMetadata = [{
        name: mockTool.name,
        version: mockTool.version,
        executionTime: toolResults[0].executionTime,
        filesProcessed: solidityFiles.length
      }];

      const vulnerabilities = await reportAggregator.deduplicateFindings(toolResults);
      const report = await reportAggregator.generateReport(vulnerabilities, toolMetadata);

      // Verify report structure
      expect(report.summary.totalVulnerabilities).toBeGreaterThan(0);
      expect(report.vulnerabilities).toBeDefined();
      expect(report.risks).toBeDefined();
      expect(report.recommendations).toBeDefined();
      expect(report.metadata).toBeDefined();

      // Step 5: Test different output formats
      const jsonReport = reportAggregator.formatReport(report, 'json');
      expect(() => JSON.parse(jsonReport)).not.toThrow();

      const htmlReport = reportAggregator.formatReport(report, 'html');
      expect(htmlReport).toContain('<!DOCTYPE html>');

      const markdownReport = reportAggregator.formatReport(report, 'markdown');
      expect(markdownReport).toContain('# Solidity Security Analysis Report');
    }, 30000);

    it('should handle multi-tool analysis and deduplication', async () => {
      // Register multiple mock tools
      const tool1 = createMockSecurityTool('MockTool1', '1.0.0');
      const tool2 = createMockSecurityTool('MockTool2', '2.0.0');
      
      toolRunner.clearTools();
      toolRunner.registerTool(tool1);
      toolRunner.registerTool(tool2);

      // Run analysis
      const toolResults = await toolRunner.runAllTools(testRepoPath);
      expect(toolResults).toHaveLength(2);

      // Test normalization and deduplication
      const normalizer = new VulnerabilityNormalizer();
      const deduplicator = new VulnerabilityDeduplicator();

      const normalizedVulns = normalizer.normalizeVulnerabilities(toolResults);
      expect(normalizedVulns.length).toBeGreaterThan(0);

      const deduplicatedVulns = deduplicator.deduplicateVulnerabilities(normalizedVulns);
      expect(deduplicatedVulns.length).toBeLessThanOrEqual(normalizedVulns.length);

      // Test cross-tool analysis
      const crossToolAnalyzer = new CrossToolAnalyzer();
      const toolNames = [tool1.name, tool2.name];
      const consensus = crossToolAnalyzer.calculateToolConsensus(deduplicatedVulns, toolNames);
      const correlations = crossToolAnalyzer.analyzeCorrelations(deduplicatedVulns);

      expect(consensus).toBeDefined();
      expect(correlations).toBeDefined();
    }, 30000);

    it('should generate comprehensive dashboard', async () => {
      const tool1 = createMockSecurityTool('MockTool1', '1.0.0');
      const tool2 = createMockSecurityTool('MockTool2', '2.0.0');
      
      toolRunner.clearTools();
      toolRunner.registerTool(tool1);
      toolRunner.registerTool(tool2);

      const toolResults = await toolRunner.runAllTools(testRepoPath);
      const toolMetadata = toolResults.map(result => ({
        name: result.toolName,
        version: result.toolVersion,
        executionTime: result.executionTime,
        filesProcessed: 5
      }));

      // Process results
      const normalizer = new VulnerabilityNormalizer();
      const deduplicator = new VulnerabilityDeduplicator();
      const crossToolAnalyzer = new CrossToolAnalyzer();

      const normalizedVulns = normalizer.normalizeVulnerabilities(toolResults);
      const deduplicatedVulns = deduplicator.deduplicateVulnerabilities(normalizedVulns);
      const consensus = crossToolAnalyzer.calculateToolConsensus(deduplicatedVulns, [tool1.name, tool2.name]);

      // Generate dashboard
      const dashboard = new AnalysisDashboard();
      const dashboardData = dashboard.generateDashboard(toolResults, toolMetadata, deduplicatedVulns, consensus);

      // Verify dashboard structure
      expect(dashboardData.overview).toBeDefined();
      expect(dashboardData.toolBreakdown).toHaveLength(2);
      expect(dashboardData.consensusView).toBeDefined();
      expect(dashboardData.timeline).toBeDefined();
      expect(dashboardData.detectionMatrix).toBeDefined();

      // Test HTML formatting
      const htmlDashboard = dashboard.formatDashboardHtml(dashboardData);
      expect(htmlDashboard).toContain('Security Analysis Dashboard');
      expect(htmlDashboard).toContain('<!DOCTYPE html>');
    }, 30000);
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle empty repositories gracefully', async () => {
      const emptyRepoPath = path.join(os.tmpdir(), 'empty-repo');
      await fs.ensureDir(emptyRepoPath);

      try {
        const solidityFiles = await repositoryManager.findSolidityFiles(emptyRepoPath);
        expect(solidityFiles).toEqual([]);

        // Should handle empty file list gracefully
        const mockTool = createMockSecurityTool();
        toolRunner.clearTools();
        toolRunner.registerTool(mockTool);

        const toolResults = await toolRunner.runAllTools(emptyRepoPath);
        expect(toolResults).toHaveLength(1);
        expect(toolResults[0].vulnerabilities).toEqual([]);
      } finally {
        await fs.remove(emptyRepoPath);
      }
    });

    it('should handle tool failures gracefully', async () => {
      const failingTool = createFailingMockTool();
      toolRunner.clearTools();
      toolRunner.registerTool(failingTool);

      const toolResults = await toolRunner.runAllTools(testRepoPath);
      expect(toolResults).toHaveLength(1);
      expect(toolResults[0].errors.length).toBeGreaterThan(0);
      expect(toolResults[0].vulnerabilities).toEqual([]);
    });

    it('should handle large repositories efficiently', async () => {
      // Create a repository with many files
      const largeRepoPath = path.join(os.tmpdir(), 'large-repo');
      await fs.ensureDir(largeRepoPath);

      try {
        // Create 50 Solidity files
        for (let i = 0; i < 50; i++) {
          await fs.writeFile(
            path.join(largeRepoPath, `Contract${i}.sol`),
            `pragma solidity ^0.8.0;\ncontract Contract${i} { function test() public {} }`
          );
        }

        const startTime = Date.now();
        const solidityFiles = await repositoryManager.findSolidityFiles(largeRepoPath);
        const discoveryTime = Date.now() - startTime;

        expect(solidityFiles).toHaveLength(50);
        expect(discoveryTime).toBeLessThan(5000); // Should complete within 5 seconds
      } finally {
        await fs.remove(largeRepoPath);
      }
    }, 30000);
  });

  describe('Performance Benchmarks', () => {
    it('should complete analysis within reasonable time limits', async () => {
      const mockTool = createMockSecurityTool();
      toolRunner.clearTools();
      toolRunner.registerTool(mockTool);

      const startTime = Date.now();
      
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);
      const toolResults = await toolRunner.runAllTools(testRepoPath);
      const vulnerabilities = await reportAggregator.deduplicateFindings(toolResults);
      
      const totalTime = Date.now() - startTime;
      
      expect(totalTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(solidityFiles.length).toBeGreaterThan(0);
      expect(toolResults.length).toBeGreaterThan(0);
    });

    it('should handle concurrent file operations efficiently', async () => {
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);
      
      const startTime = Date.now();
      
      // Read all files concurrently
      const fileContents = await Promise.all(
        solidityFiles.map(file => repositoryManager.readFileContent(file))
      );
      
      const readTime = Date.now() - startTime;
      
      expect(fileContents).toHaveLength(solidityFiles.length);
      expect(fileContents.every(content => content.length > 0)).toBe(true);
      expect(readTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});

async function createTestContracts(repoPath: string): Promise<void> {
  const contracts = {
    'VulnerableContract.sol': `
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State change after external call
    }
    
    // Integer overflow vulnerability (pre-0.8.0 style)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // Could overflow
    }
    
    // Unchecked call return value
    function unsafeTransfer(address to, uint256 amount) public {
        to.call{value: amount}(""); // Return value not checked
    }
    
    // Timestamp dependence
    function timestampDependentFunction() public view returns (bool) {
        return block.timestamp % 2 == 0; // Vulnerable to miner manipulation
    }
}`,

    'AccessControlIssues.sol': `
pragma solidity ^0.8.0;

contract AccessControlIssues {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Missing access control
    function changeOwner(address newOwner) public {
        owner = newOwner; // Anyone can change owner
    }
    
    // Weak access control
    function sensitiveFunction() public {
        require(msg.sender == owner, "Not owner");
        // But owner can be changed by anyone
    }
}`,

    'DoSVulnerable.sol': `
pragma solidity ^0.8.0;

contract DoSVulnerable {
    address[] public participants;
    
    // DoS with unbounded loop
    function distributeRewards() public {
        for (uint i = 0; i < participants.length; i++) {
            // This could run out of gas with many participants
            payable(participants[i]).transfer(1 ether);
        }
    }
    
    function addParticipant(address participant) public {
        participants.push(participant);
    }
}`,

    'src/utils/Helper.sol': `
pragma solidity ^0.8.0;

library Helper {
    // Front-running vulnerability
    function calculateReward(uint256 amount) public view returns (uint256) {
        return amount * block.timestamp; // Predictable calculation
    }
}`,

    'test/TestContract.sol': `
pragma solidity ^0.8.0;

contract TestContract {
    function testFunction() public pure returns (bool) {
        return true;
    }
}`
  };

  for (const [fileName, content] of Object.entries(contracts)) {
    const filePath = path.join(repoPath, fileName);
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, content);
  }
}

function createMockSecurityTool(name: string = 'MockTool', version: string = '1.0.0') {
  return {
    name,
    version,
    description: 'Mock security tool for testing',
    
    async execute(repoPath: string) {
      // Simulate analysis time
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        toolName: name,
        toolVersion: version,
        executionTime: 100,
        vulnerabilities: [
          {
            type: 'reentrancy' as any,
            severity: 'High' as any,
            file: 'VulnerableContract.sol',
            lineNumber: 10,
            codeSnippet: 'msg.sender.call{value: amount}("");',
            description: 'Potential reentrancy vulnerability detected',
            recommendation: 'Use checks-effects-interactions pattern',
            toolSource: name,
            confidence: 0.8
          },
          {
            type: 'access_control' as any,
            severity: 'Medium' as any,
            file: 'AccessControlIssues.sol',
            lineNumber: 15,
            codeSnippet: 'function changeOwner(address newOwner) public',
            description: 'Missing access control on sensitive function',
            recommendation: 'Add proper access control modifiers',
            toolSource: name,
            confidence: 0.9
          }
        ],
        errors: [],
        metadata: { filesProcessed: 5 }
      };
    },
    
    parseOutput(rawOutput: string) {
      return [];
    },
    
    async isAvailable() {
      return true;
    }
  };
}

function createFailingMockTool() {
  return {
    name: 'FailingTool',
    version: '1.0.0',
    description: 'Mock tool that always fails',
    
    async execute(repoPath: string) {
      throw new Error('Mock tool failure for testing');
    },
    
    parseOutput(rawOutput: string) {
      return [];
    },
    
    async isAvailable() {
      return true;
    }
  };
}