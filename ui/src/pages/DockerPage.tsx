import { useState, useEffect, useCallback } from 'react'
import {
  Play,
  Square,
  RefreshCw,
  ExternalLink,
  Terminal,
  Database,
  Globe,
  Server,
  AlertCircle,
  CheckCircle,
  Loader2,
} from 'lucide-react'
import {
  DockerService,
  getServices,
  startService,
  stopService,
  startAllServices,
  stopAllServices,
  checkHealth,
} from '../services/dockerApi'

const categoryIcons = {
  web: Globe,
  database: Database,
  os: Server,
  service: Terminal,
}

// Polling interval in milliseconds
const POLL_INTERVAL = 5000

export default function DockerPage() {
  const [services, setServices] = useState<DockerService[]>([])
  const [filter, setFilter] = useState<string>('all')
  const [loading, setLoading] = useState(true)
  const [apiConnected, setApiConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)

  // Fetch services from API
  const fetchServices = useCallback(async () => {
    try {
      const response = await getServices()
      setServices(response.services)
      setApiConnected(true)
      setError(null)
    } catch (err) {
      setApiConnected(false)
      setError(
        err instanceof Error ? err.message : 'Failed to connect to Docker API'
      )
    } finally {
      setLoading(false)
    }
  }, [])

  // Check API health
  const checkApiHealth = useCallback(async () => {
    try {
      const health = await checkHealth()
      setApiConnected(health.status === 'healthy')
      if (health.status !== 'healthy') {
        setError('Docker API is in degraded state')
      }
    } catch {
      setApiConnected(false)
    }
  }, [])

  // Initial load and polling
  useEffect(() => {
    fetchServices()

    const pollInterval = setInterval(() => {
      if (!actionInProgress) {
        fetchServices()
      }
    }, POLL_INTERVAL)

    return () => clearInterval(pollInterval)
  }, [fetchServices, actionInProgress])

  const filteredServices =
    filter === 'all'
      ? services
      : services.filter((s) => s.category === filter)

  const runningCount = services.filter((s) => s.status === 'running').length

  const handleStartAll = async () => {
    setActionInProgress('start-all')
    try {
      await startAllServices()
      // Wait a bit then refresh
      setTimeout(fetchServices, 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start services')
    } finally {
      setActionInProgress(null)
    }
  }

  const handleStopAll = async () => {
    setActionInProgress('stop-all')
    try {
      await stopAllServices()
      // Wait a bit then refresh
      setTimeout(fetchServices, 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop services')
    } finally {
      setActionInProgress(null)
    }
  }

  const toggleService = async (serviceId: string, currentStatus: string) => {
    setActionInProgress(serviceId)

    // Optimistically update the UI
    setServices((prev) =>
      prev.map((s) =>
        s.id === serviceId ? { ...s, status: 'starting' as const } : s
      )
    )

    try {
      if (currentStatus === 'running') {
        await stopService(serviceId)
      } else {
        await startService(serviceId)
      }
      // Refresh to get actual status
      setTimeout(fetchServices, 2000)
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to toggle service'
      )
      // Revert on error
      fetchServices()
    } finally {
      setActionInProgress(null)
    }
  }

  const handleRefresh = () => {
    setLoading(true)
    fetchServices()
  }

  if (loading && services.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-cyber-white animate-spin mx-auto mb-4" />
          <p className="text-cyber-muted">Loading Docker services...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Connection Status Banner */}
      {!apiConnected && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400" />
          <div className="flex-1">
            <p className="text-red-400 font-medium">Docker API Not Connected</p>
            <p className="text-red-400/70 text-sm">
              Start the Docker API server: <code className="bg-cyber-dark px-2 py-0.5 rounded">python tools/docker-api/app.py</code>
            </p>
          </div>
          <button
            onClick={handleRefresh}
            className="flex items-center gap-2 px-3 py-1.5 text-sm border border-red-500/30 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Retry
          </button>
        </div>
      )}

      {/* Error Banner */}
      {error && apiConnected && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-yellow-400" />
          <p className="text-yellow-400 flex-1">{error}</p>
          <button
            onClick={() => setError(null)}
            className="text-yellow-400 hover:text-yellow-300"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-cyber-white mb-2">
            Docker Services
          </h1>
          <div className="flex items-center gap-3">
            <p className="text-cyber-muted">
              Manage vulnerable systems and target environments
            </p>
            {apiConnected && (
              <span className="flex items-center gap-1 text-xs text-green-400">
                <CheckCircle className="w-3 h-3" />
                API Connected
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-cyber-muted">
            {runningCount}/{services.length} running
          </span>
          <button
            onClick={handleRefresh}
            disabled={loading}
            className="p-2 border border-cyber-border rounded-lg text-cyber-muted hover:text-cyber-white hover:border-cyber-white transition-colors disabled:opacity-50"
            title="Refresh status"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <div className="flex gap-2">
            <button
              onClick={handleStartAll}
              disabled={!apiConnected || actionInProgress === 'start-all'}
              className="flex items-center gap-2 px-4 py-2 bg-cyber-white text-cyber-black rounded-lg font-medium hover:bg-cyber-muted transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {actionInProgress === 'start-all' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              Start All
            </button>
            <button
              onClick={handleStopAll}
              disabled={!apiConnected || actionInProgress === 'stop-all'}
              className="flex items-center gap-2 px-4 py-2 border border-cyber-border rounded-lg text-cyber-white hover:bg-cyber-card transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {actionInProgress === 'stop-all' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Square className="w-4 h-4" />
              )}
              Stop All
            </button>
          </div>
        </div>
      </div>

      {/* Quick Commands */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
        <h3 className="text-sm font-medium text-cyber-muted mb-3">
          Quick Commands
        </h3>
        <div className="flex flex-wrap gap-2">
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker-compose up -d
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker-compose down
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker ps
          </code>
          <code className="px-3 py-1 bg-cyber-dark rounded text-xs text-cyber-white font-mono">
            docker logs -f [container]
          </code>
        </div>
      </div>

      {/* Category Filter */}
      <div className="flex gap-2">
        {['all', 'web', 'database', 'os', 'service'].map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              filter === cat
                ? 'bg-cyber-white text-cyber-black'
                : 'text-cyber-muted hover:text-cyber-white hover:bg-cyber-card'
            }`}
          >
            {cat.charAt(0).toUpperCase() + cat.slice(1)}
          </button>
        ))}
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredServices.map((service) => {
          const Icon = categoryIcons[service.category] || Terminal
          const isActionInProgress = actionInProgress === service.id
          return (
            <div
              key={service.id}
              className="bg-cyber-card border border-cyber-border rounded-xl p-6 hover:border-cyber-white/20 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-cyber-dark border border-cyber-border rounded-lg flex items-center justify-center">
                    <Icon className="w-5 h-5 text-cyber-muted" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-cyber-white">
                      {service.name}
                    </h3>
                    <p className="text-xs text-cyber-muted font-mono">
                      {service.container}
                    </p>
                  </div>
                </div>
                <span
                  className={`status-dot ${
                    service.status === 'running'
                      ? 'status-running'
                      : service.status === 'starting'
                      ? 'status-starting'
                      : 'status-stopped'
                  }`}
                />
              </div>

              <p className="text-sm text-cyber-muted mb-4">
                {service.description}
              </p>

              {service.port && (
                <p className="text-xs text-cyber-disabled mb-4 font-mono">
                  Port: {service.port}
                </p>
              )}

              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleService(service.id, service.status)}
                  disabled={!apiConnected || isActionInProgress}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                    service.status === 'running'
                      ? 'bg-cyber-dark border border-cyber-border text-cyber-white hover:border-cyber-white'
                      : 'bg-cyber-white text-cyber-black hover:bg-cyber-muted'
                  }`}
                >
                  {isActionInProgress || service.status === 'starting' ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      {service.status === 'starting' ? 'Starting...' : 'Processing...'}
                    </>
                  ) : service.status === 'running' ? (
                    <>
                      <Square className="w-4 h-4" />
                      Stop
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Start
                    </>
                  )}
                </button>
                {service.port && service.status === 'running' && (
                  <a
                    href={`http://localhost:${service.port}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 border border-cyber-border rounded-lg text-cyber-muted hover:text-cyber-white hover:border-cyber-white transition-colors"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Empty State */}
      {filteredServices.length === 0 && services.length > 0 && (
        <div className="text-center py-12">
          <p className="text-cyber-muted">
            No services found in this category.
          </p>
        </div>
      )}

      {/* Network Info */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-bold text-cyber-white mb-4">
          Network Configuration
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Lab Network</p>
            <p className="text-cyber-white font-mono">172.20.0.0/16</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Isolated Web</p>
            <p className="text-cyber-white font-mono">172.21.0.0/24</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-sm text-cyber-muted mb-1">Isolated DB</p>
            <p className="text-cyber-white font-mono">172.22.0.0/24</p>
          </div>
        </div>
      </div>
    </div>
  )
}
