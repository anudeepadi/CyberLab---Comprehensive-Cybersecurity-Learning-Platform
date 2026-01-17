/**
 * Docker API Service
 * Provides functions to interact with the Docker management API
 */

const API_BASE_URL = import.meta.env.VITE_DOCKER_API_URL || 'http://localhost:5001';

export interface DockerService {
  id: string;
  name: string;
  container: string;
  port: number | null;
  status: 'running' | 'stopped' | 'starting';
  category: 'web' | 'database' | 'os' | 'service';
  description: string;
}

export interface ServicesResponse {
  services: DockerService[];
  running_count: number;
  total_count: number;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded';
  docker_available: boolean;
  compose_file_exists: boolean;
  compose_path: string;
}

export interface ServiceActionResponse {
  success: boolean;
  service: string;
  status?: string;
  message?: string;
  error?: string;
}

export interface LogsResponse {
  service: string;
  logs: string;
}

class DockerApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public response?: unknown
  ) {
    super(message);
    this.name = 'DockerApiError';
  }
}

async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      throw new DockerApiError(
        data.error || `Request failed with status ${response.status}`,
        response.status,
        data
      );
    }

    return data as T;
  } catch (error) {
    if (error instanceof DockerApiError) {
      throw error;
    }
    throw new DockerApiError(
      error instanceof Error ? error.message : 'Network error'
    );
  }
}

/**
 * Check API health status
 */
export async function checkHealth(): Promise<HealthResponse> {
  return fetchApi<HealthResponse>('/health');
}

/**
 * Get all services with their current status
 */
export async function getServices(): Promise<ServicesResponse> {
  return fetchApi<ServicesResponse>('/services');
}

/**
 * Start a specific service
 */
export async function startService(
  serviceName: string
): Promise<ServiceActionResponse> {
  return fetchApi<ServiceActionResponse>(`/services/${serviceName}/start`, {
    method: 'POST',
  });
}

/**
 * Stop a specific service
 */
export async function stopService(
  serviceName: string
): Promise<ServiceActionResponse> {
  return fetchApi<ServiceActionResponse>(`/services/${serviceName}/stop`, {
    method: 'POST',
  });
}

/**
 * Start all services
 */
export async function startAllServices(): Promise<ServiceActionResponse> {
  return fetchApi<ServiceActionResponse>('/services/start-all', {
    method: 'POST',
  });
}

/**
 * Stop all services
 */
export async function stopAllServices(): Promise<ServiceActionResponse> {
  return fetchApi<ServiceActionResponse>('/services/stop-all', {
    method: 'POST',
  });
}

/**
 * Get logs for a specific service
 */
export async function getServiceLogs(
  serviceName: string,
  lines: number = 100
): Promise<LogsResponse> {
  return fetchApi<LogsResponse>(`/services/${serviceName}/logs?lines=${lines}`);
}

/**
 * Check if the Docker API is available
 */
export async function isApiAvailable(): Promise<boolean> {
  try {
    await checkHealth();
    return true;
  } catch {
    return false;
  }
}
