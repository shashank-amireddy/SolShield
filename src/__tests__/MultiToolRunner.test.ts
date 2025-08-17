import { SecurityToolRunner } from '../core/MultiToolRunner';
import { SecurityTool, ToolResult, Vulnerability, VulnerabilityType } from '../types';

// Mock ConfigManager
jest.mock('../utils/config', () => ({
  ConfigManager: {
    getInstance: jest.fn(() => ({
      getTimeout: jest.fn(() => 30000),
    }))
  }
}));

describe('SecurityToolRunner', () => {
  let toolRunner: SecurityToolRunner;
  let mockTool: jest.Mocked<SecurityTool>;
  let mockTool2: jest.Mocked<SecurityTool>;

  beforeEach(() => {
    jest.clearAllMocks();
    toolRunner = new SecurityToolRunner();
    
    // Create mock tools
    mockTool = {
      name: 'TestTool',
      version: '1.0.0',
      description: 'Test security tool',
      execute: jest.fn(),
      parseOutput: jest.fn(),
      isAvailable: jest.fn()
    };

    mockTool2 = {
      name: 'TestTool2',
      version: '2.0.0',
      description: 'Second test security tool',
      execute: jest.fn(),
      parseOutput: jest.fn(),
      isAvailable: jest.fn()
    };
  });

  describe('registerTool', () => {
    it('should successfully register a valid tool', () => {
      expect(() => toolRunner.registerTool(mockTool)).not.toThrow();
      
      const availableTools = toolRunner.getAvailableTools();
      expect(availableTools).toHaveLength(1);
      expect(availableTools[0]).toBe(mockTool);
    });

    it('should throw error for tool without name', () => {
      const invalidTool = { ...mockTool, name: '' };
      
      expect(() => toolRunner.registerTool(invalidTool))
        .toThrow('Tool must have a name and version');
    });

    it('should throw error for tool without version', () => {
      const invalidTool = { ...mockTool, version: '' };
      
      expect(() => toolRunner.registerTool(invalidTool))
        .toThrow('Tool must have a name and version');
    });

    it('should overwrite existing tool with same name', () => {
      toolRunner.registerTool(mockTool);
      
      const updatedTool = { ...mockTool, version: '1.1.0' };
      toolRunner.registerTool(updatedTool);
      
      const availableTools = toolRunner.getAvailableTools();
      expect(availableTools).toHaveLength(1);
      expect(availableTools[0].version).toBe('1.1.0');
    });

    it('should register multiple different tools', () => {
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const availableTools = toolRunner.getAvailableTools();
      expect(availableTools).toHaveLength(2);
    });
  });

  describe('getAvailableTools', () => {
    it('should return empty array when no tools registered', () => {
      const tools = toolRunner.getAvailableTools();
      expect(tools).toEqual([]);
    });

    it('should return all registered tools', () => {
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const tools = toolRunner.getAvailableTools();
      expect(tools).toHaveLength(2);
      expect(tools).toContain(mockTool);
      expect(tools).toContain(mockTool2);
    });
  });

  describe('getRegisteredToolNames', () => {
    it('should return tool names', () => {
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const names = toolRunner.getRegisteredToolNames();
      expect(names).toEqual(['TestTool', 'TestTool2']);
    });
  });

  describe('getTool', () => {
    it('should return specific tool by name', () => {
      toolRunner.registerTool(mockTool);
      
      const tool = toolRunner.getTool('TestTool');
      expect(tool).toBe(mockTool);
    });

    it('should return undefined for non-existent tool', () => {
      const tool = toolRunner.getTool('NonExistent');
      expect(tool).toBeUndefined();
    });
  });

  describe('unregisterTool', () => {
    it('should remove tool and return true', () => {
      toolRunner.registerTool(mockTool);
      
      const removed = toolRunner.unregisterTool('TestTool');
      expect(removed).toBe(true);
      expect(toolRunner.getAvailableTools()).toHaveLength(0);
    });

    it('should return false for non-existent tool', () => {
      const removed = toolRunner.unregisterTool('NonExistent');
      expect(removed).toBe(false);
    });
  });

  describe('clearTools', () => {
    it('should remove all tools', () => {
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      toolRunner.clearTools();
      expect(toolRunner.getAvailableTools()).toHaveLength(0);
    });
  });

  describe('runAllTools', () => {
    const mockResult: ToolResult = {
      toolName: 'TestTool',
      toolVersion: '1.0.0',
      executionTime: 1000,
      vulnerabilities: [],
      errors: [],
      metadata: {}
    };

    it('should return empty array when no tools registered', async () => {
      const results = await toolRunner.runAllTools('/test/repo');
      expect(results).toEqual([]);
    });

    it('should run all available tools', async () => {
      mockTool.isAvailable.mockResolvedValue(true);
      mockTool.execute.mockResolvedValue(mockResult);
      
      toolRunner.registerTool(mockTool);
      
      const results = await toolRunner.runAllTools('/test/repo');
      
      expect(results).toHaveLength(1);
      expect(mockTool.isAvailable).toHaveBeenCalled();
      expect(mockTool.execute).toHaveBeenCalledWith('/test/repo', undefined);
    });

    it('should skip unavailable tools', async () => {
      mockTool.isAvailable.mockResolvedValue(false);
      mockTool2.isAvailable.mockResolvedValue(true);
      mockTool2.execute.mockResolvedValue({ ...mockResult, toolName: 'TestTool2' });
      
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const results = await toolRunner.runAllTools('/test/repo');
      
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe('TestTool2');
      expect(mockTool.execute).not.toHaveBeenCalled();
      expect(mockTool2.execute).toHaveBeenCalled();
    });

    it('should handle tool execution failures gracefully', async () => {
      mockTool.isAvailable.mockResolvedValue(true);
      mockTool.execute.mockRejectedValue(new Error('Tool execution failed'));
      
      toolRunner.registerTool(mockTool);
      
      const results = await toolRunner.runAllTools('/test/repo');
      
      expect(results).toHaveLength(1);
      expect(results[0].errors).toContain('Tool execution failed');
      expect(results[0].vulnerabilities).toEqual([]);
    });

    it('should run tools in parallel', async () => {
      const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
      
      mockTool.isAvailable.mockResolvedValue(true);
      mockTool.execute.mockImplementation(async () => {
        await delay(100);
        return mockResult;
      });
      
      mockTool2.isAvailable.mockResolvedValue(true);
      mockTool2.execute.mockImplementation(async () => {
        await delay(100);
        return { ...mockResult, toolName: 'TestTool2' };
      });
      
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const startTime = Date.now();
      const results = await toolRunner.runAllTools('/test/repo');
      const endTime = Date.now();
      
      expect(results).toHaveLength(2);
      // Should complete in roughly 100ms (parallel) rather than 200ms (sequential)
      expect(endTime - startTime).toBeLessThan(150);
    });
  });

  describe('runSpecificTools', () => {
    const mockResult: ToolResult = {
      toolName: 'TestTool',
      toolVersion: '1.0.0',
      executionTime: 1000,
      vulnerabilities: [],
      errors: [],
      metadata: {}
    };

    it('should return empty array for empty tool list', async () => {
      const results = await toolRunner.runSpecificTools('/test/repo', []);
      expect(results).toEqual([]);
    });

    it('should run only specified tools', async () => {
      mockTool.isAvailable.mockResolvedValue(true);
      mockTool.execute.mockResolvedValue(mockResult);
      mockTool2.isAvailable.mockResolvedValue(true);
      mockTool2.execute.mockResolvedValue({ ...mockResult, toolName: 'TestTool2' });
      
      toolRunner.registerTool(mockTool);
      toolRunner.registerTool(mockTool2);
      
      const results = await toolRunner.runSpecificTools('/test/repo', ['TestTool']);
      
      expect(results).toHaveLength(1);
      expect(results[0].toolName).toBe('TestTool');
      expect(mockTool.execute).toHaveBeenCalled();
      expect(mockTool2.execute).not.toHaveBeenCalled();
    });

    it('should throw error when no requested tools are available', async () => {
      await expect(toolRunner.runSpecificTools('/test/repo', ['NonExistent']))
        .rejects.toThrow('None of the requested tools are available');
    });

    it('should throw error when requested tools are not available', async () => {
      mockTool.isAvailable.mockResolvedValue(false);
      toolRunner.registerTool(mockTool);
      
      await expect(toolRunner.runSpecificTools('/test/repo', ['TestTool']))
        .rejects.toThrow('None of the requested tools are available');
    });
  });
});