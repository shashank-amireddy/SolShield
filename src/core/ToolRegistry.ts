import { SecurityTool } from '../types';
import { SlitherTool } from '../tools/SlitherTool';
import { MythrilTool } from '../tools/MythrilTool';
import { SmartCheckTool } from '../tools/SmartCheckTool';
import { SolhintTool } from '../tools/SolhintTool';
import { Securify2Tool } from '../tools/Securify2Tool';

export class ToolRegistry {
  private static instance: ToolRegistry;
  private availableToolClasses: Map<string, new () => SecurityTool> = new Map();

  private constructor() {
    this.registerBuiltInTools();
  }

  static getInstance(): ToolRegistry {
    if (!ToolRegistry.instance) {
      ToolRegistry.instance = new ToolRegistry();
    }
    return ToolRegistry.instance;
  }

  private registerBuiltInTools(): void {
    this.availableToolClasses.set('slither', SlitherTool);
    this.availableToolClasses.set('mythril', MythrilTool);
    this.availableToolClasses.set('smartcheck', SmartCheckTool);
    this.availableToolClasses.set('solhint', SolhintTool);
    this.availableToolClasses.set('securify2', Securify2Tool);
  }

  registerToolClass(name: string, toolClass: new () => SecurityTool): void {
    this.availableToolClasses.set(name.toLowerCase(), toolClass);
  }

  createTool(name: string): SecurityTool | null {
    const ToolClass = this.availableToolClasses.get(name.toLowerCase());
    if (!ToolClass) {
      return null;
    }

    try {
      return new ToolClass();
    } catch (error) {
      console.error(`Failed to create tool ${name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }

  getAvailableToolNames(): string[] {
    return Array.from(this.availableToolClasses.keys());
  }

  createAllTools(): SecurityTool[] {
    const tools: SecurityTool[] = [];
    
    for (const [name, ToolClass] of this.availableToolClasses) {
      try {
        const tool = new ToolClass();
        tools.push(tool);
      } catch (error) {
        console.warn(`Failed to create tool ${name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    return tools;
  }

  async createAvailableTools(): Promise<SecurityTool[]> {
    const allTools = this.createAllTools();
    const availableTools: SecurityTool[] = [];

    for (const tool of allTools) {
      try {
        if (await tool.isAvailable()) {
          availableTools.push(tool);
        }
      } catch (error) {
        console.warn(`Failed to check availability of ${tool.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    return availableTools;
  }
}