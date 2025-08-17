import { ConfigManager } from '../utils/config';

describe('ConfigManager', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Clear environment variables
    delete process.env.GITHUB_TOKEN;
    delete process.env.SCANNER_TEMP_DIR;
    delete process.env.SCANNER_TIMEOUT;
    delete process.env.SCANNER_MAX_RETRIES;

    // Reset singleton instance
    (ConfigManager as any).instance = undefined;
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('getInstance', () => {
    it('should return singleton instance', () => {
      const instance1 = ConfigManager.getInstance();
      const instance2 = ConfigManager.getInstance();
      
      expect(instance1).toBe(instance2);
    });
  });

  describe('environment variable loading', () => {
    it('should load configuration from environment variables', () => {
      process.env.GITHUB_TOKEN = 'test-token';
      process.env.SCANNER_TEMP_DIR = '/custom/temp';
      process.env.SCANNER_TIMEOUT = '60000';
      process.env.SCANNER_MAX_RETRIES = '5';

      const config = ConfigManager.getInstance();

      expect(config.getGitHubToken()).toBe('test-token');
      expect(config.getTempDir()).toBe('/custom/temp');
      expect(config.getTimeout()).toBe(60000);
      expect(config.getMaxRetries()).toBe(5);
    });

    it('should use default values when environment variables are not set', () => {
      const config = ConfigManager.getInstance();

      expect(config.getGitHubToken()).toBeUndefined();
      expect(config.getTempDir()).toBeUndefined();
      expect(config.getTimeout()).toBe(300000); // 5 minutes default
      expect(config.getMaxRetries()).toBe(3);
    });

    it('should handle invalid numeric environment variables', () => {
      process.env.SCANNER_TIMEOUT = 'invalid';
      process.env.SCANNER_MAX_RETRIES = 'also-invalid';

      const config = ConfigManager.getInstance();

      expect(config.getTimeout()).toBe(300000); // Default value
      expect(config.getMaxRetries()).toBe(3); // Default value
    });
  });

  describe('setConfig', () => {
    it('should allow updating configuration', () => {
      const config = ConfigManager.getInstance();
      
      config.setConfig({
        githubToken: 'new-token',
        timeout: 120000
      });

      expect(config.getGitHubToken()).toBe('new-token');
      expect(config.getTimeout()).toBe(120000);
    });

    it('should merge with existing configuration', () => {
      process.env.GITHUB_TOKEN = 'env-token';
      process.env.SCANNER_MAX_RETRIES = '5';

      const config = ConfigManager.getInstance();
      
      config.setConfig({
        timeout: 120000
      });

      expect(config.getGitHubToken()).toBe('env-token'); // Should keep existing
      expect(config.getTimeout()).toBe(120000); // Should update
      expect(config.getMaxRetries()).toBe(5); // Should keep existing
    });
  });

  describe('getConfig', () => {
    it('should return a copy of the configuration', () => {
      const config = ConfigManager.getInstance();
      const configCopy = config.getConfig();
      
      // Modify the copy
      configCopy.githubToken = 'modified';
      
      // Original should be unchanged
      expect(config.getGitHubToken()).not.toBe('modified');
    });
  });
});