import { ToolRegistry } from '../core/ToolRegistry';
import { SecurityTool } from '../types';

// Mock the tool imports
jest.mock('../tools/SlitherTool', () => ({
  SlitherTool: jest.fn().mockImplementation(() => ({
    name: 'Slither',
    version: '0.9.6',
    description: 'Fast static analysis tool'
  }))
}));

jest.mock('../tools/MythrilTool', () => ({
  MythrilTool: jest.fn().mockImplementation(() => ({
    name: 'Mythril',
    version: '0.23.0',
    description: 'Symbolic execution tool'
  }))
}));

jest.mock('../tools/SmartCheckTool', () => ({
  SmartCheckTool: jest.fn().mockImplementation(() => ({
    name: 'SmartCheck',
    version: '2.0.0',
    description: 'Pattern-based analysis tool'
  }))
}));

jest.mock('../tools/SolhintTool', () => ({
  SolhintTool: jest.fn().mockImplementation(() => ({
    name: 'Solhint',
    version: '3.4.0',
    description: 'Linting tool'
  }))
}));

jest.mock('../tools/Securify2Tool', () => ({
  Securify2Tool: jest.fn().mockImplementation(() => ({
    name: 'Securify2',
    version: '1.0.0',
    description: 'Formal verification tool'
  }))
}));

describe('ToolRegistry', () => {
  let registry: ToolRegistry;

  beforeEach(() => {
    // Reset singleton instance
    (ToolRegistry as any).instance = undefined;
    registry = ToolRegistry.getInstance();
  });

  describe('getInstance', () => {
    it('should return singleton instance', () => {
      const instance1 = ToolRegistry.getInstance();
      const instance2 = ToolRegistry.getInstance();
      
      expect(instance1).toBe(instance2);
    });
  });

  describe('built-in tools', () => {
    it('should have all built-in tools registered', () => {
      const availableTools = registry.getAvailableToolNames();
      
      expect(availableTools).toContain('slither');
      expect(availableTools).toContain('mythril');
      expect(availableTools).toContain('smartcheck');
      expect(availableTools).toContain('solhint');
      expect(availableTools).toContain('securify2');
    });

    it('should have all tools enabled by default', () => {
      const enabledTools = registry.getEnabledToolNames();
      
      expect(enabledTools).toContain('slither');
      expect(enabledTools).toContain('mythril');
      expect(enabledTools).toContain('smartcheck');
      expect(enabledTools).toContain('solhint');
      expect(enabledTools).toContain('securify2');
    });
  });

  describe('createTool', () => {
    it('should create tool by name', () => {
      const tool = registry.createTool('slither');
      
      expect(tool).toBeTruthy();
      expect(tool?.name).toBe('Slither');
    });

    it('should return null for unknown tool', () => {
      const tool = registry.createTool('unknown');
      
      expect(tool).toBeNull();
    });

    it('should be case insensitive', () => {
      const tool1 = registry.createTool('SLITHER');
      const tool2 = registry.createTool('Slither');
      const tool3 = registry.createTool('slither');
      
      expect(tool1?.name).toBe('Slither');
      expect(tool2?.name).toBe('Slither');
      expect(tool3?.name).toBe('Slither');
    });
  });

  describe('createAllEnabledTools', () => {
    it('should create all enabled tools', () => {
      const tools = registry.createAllEnabledTools();
      
      expect(tools).toHaveLength(5); // All 5 built-in tools
      expect(tools.map(t => t.name)).toContain('Slither');
      expect(tools.map(t => t.name)).toContain('Mythril');
    });

    it('should only create enabled tools', () => {
      registry.disableTool('slither');
      registry.disableTool('mythril');
      
      const tools = registry.createAllEnabledTools();
      
      expect(tools).toHaveLength(3);
      expect(tools.map(t => t.name)).not.toContain('Slither');
      expect(tools.map(t => t.name)).not.toContain('Mythril');
    });
  });

  describe('createSpecificTools', () => {
    it('should create only specified tools', () => {
      const tools = registry.createSpecificTools(['slither', 'mythril']);
      
      expect(tools).toHaveLength(2);
      expect(tools.map(t => t.name)).toContain('Slither');
      expect(tools.map(t => t.name)).toContain('Mythril');
    });

    it('should skip unknown tools', () => {
      const tools = registry.createSpecificTools(['slither', 'unknown', 'mythril']);
      
      expect(tools).toHaveLength(2);
      expect(tools.map(t => t.name)).toContain('Slither');
      expect(tools.map(t => t.name)).toContain('Mythril');
    });

    it('should return empty array for all unknown tools', () => {
      const tools = registry.createSpecificTools(['unknown1', 'unknown2']);
      
      expect(tools).toHaveLength(0);
    });
  });

  describe('tool configuration', () => {
    it('should check if tool is enabled', () => {
      expect(registry.isToolEnabled('slither')).toBe(true);
      expect(registry.isToolEnabled('unknown')).toBe(false);
    });

    it('should enable and disable tools', () => {
      registry.disableTool('slither');
      expect(registry.isToolEnabled('slither')).toBe(false);
      
      registry.enableTool('slither');
      expect(registry.isToolEnabled('slither')).toBe(true);
    });

    it('should set tool configuration', () => {
      const config = { enabled: false, options: { timeout: 5000 } };
      registry.setToolConfig('slither', config);
      
      const retrievedConfig = registry.getToolConfig('slither');
      expect(retrievedConfig).toEqual(config);
    });

    it('should update configuration', () => {
      const newConfig = {
        slither: { enabled: false },
        mythril: { enabled: false }
      };
      
      registry.updateConfig(newConfig);
      
      expect(registry.isToolEnabled('slither')).toBe(false);
      expect(registry.isToolEnabled('mythril')).toBe(false);
      expect(registry.isToolEnabled('smartcheck')).toBe(true); // Should remain unchanged
    });

    it('should reset to defaults', () => {
      registry.disableTool('slither');
      registry.disableTool('mythril');
      
      registry.resetToDefaults();
      
      expect(registry.isToolEnabled('slither')).toBe(true);
      expect(registry.isToolEnabled('mythril')).toBe(true);
    });
  });

  describe('custom tool registration', () => {
    it('should register custom tool', () => {
      const mockTool: SecurityTool = {
        name: 'CustomTool',
        version: '1.0.0',
        description: 'Custom security tool',
        execute: jest.fn(),
        parseOutput: jest.fn(),
        isAvailable: jest.fn()
      };

      registry.registerTool('custom', () => mockTool);
      
      const availableTools = registry.getAvailableToolNames();
      expect(availableTools).toContain('custom');
      
      const createdTool = registry.createTool('custom');
      expect(createdTool).toBe(mockTool);
    });

    it('should handle tool creation errors', () => {
      registry.registerTool('failing', () => {
        throw new Error('Tool creation failed');
      });
      
      const tool = registry.createTool('failing');
      expect(tool).toBeNull();
    });
  });
});