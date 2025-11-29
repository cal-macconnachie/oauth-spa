/**
 * OAuth Redirect SPA
 * Handles OAuth flows for multiple domains without redeploying infrastructure
 */

// Configuration
const COGNITO_CONFIG = {
  region: 'us-east-1',
  userPoolId: 'us-east-1_c0hPAs0Us',
  clientId: '37u4esg6blk7sdbqvjhlbjh3hk',
  domain: 'https://auth.cals-api.com',
  redirectUri: 'https://oauth.cals-api.com/auth/callback', // Production
  // redirectUri: 'http://localhost:8080/auth/callback', // Local dev
}

// Allowed domains for return URLs (security whitelist)
const ALLOWED_DOMAINS = [
  'cals-api.com',
  '*.cals-api.com',
  '*.csm.codes',
  'csm.codes',
  'localhost:*',
]

// OAuth intent stored in localStorage
interface OAuthIntent {
  returnUrl: string
  provider: 'google' | 'apple'
  timestamp: number
}

// PKCE helpers
function generateRandomString(length: number): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
  const values = new Uint8Array(length)
  crypto.getRandomValues(values)
  return Array.from(values)
    .map((v) => charset[v % charset.length])
    .join('')
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(codeVerifier)
  const hash = await crypto.subtle.digest('SHA-256', data)

  // Convert to base64url
  const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function setupPKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = generateRandomString(128)
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  // Store code verifier in sessionStorage for later use in callback
  sessionStorage.setItem('pkce_code_verifier', codeVerifier)

  return { codeVerifier, codeChallenge }
}

// State parameter for CSRF protection
function generateState(): string {
  const state = generateRandomString(32)
  sessionStorage.setItem('oauth_state', state)
  return state
}

// Match a hostname/host against a domain pattern with wildcards
function matchesDomainPattern(host: string, pattern: string): boolean {
  // Handle port wildcards (e.g., localhost:*)
  if (pattern.includes(':*')) {
    const [patternHostname] = pattern.split(':')
    const [hostname] = host.split(':')
    return hostname === patternHostname
  }

  // Handle subdomain wildcards (e.g., *.example.com)
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.slice(2) // Remove "*."
    const [hostname] = host.split(':') // Ignore port for hostname matching

    // Match if hostname is exactly the base domain or ends with .baseDomain
    return hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)
  }

  // Exact match (ignore port for hostname-only patterns)
  const [hostname] = host.split(':')
  const [patternHostname] = pattern.split(':')
  return hostname === patternHostname || host === pattern
}

// Validate return URL against whitelist
function validateReturnUrl(url: string): boolean {
  try {
    const parsed = new URL(url)
    const host = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname

    return ALLOWED_DOMAINS.some((pattern) => matchesDomainPattern(host, pattern))
  } catch {
    return false
  }
}

// Store OAuth intent before redirecting to provider
function storeOAuthIntent(returnUrl: string, provider: 'google' | 'apple'): void {
  if (!validateReturnUrl(returnUrl)) {
    throw new Error('Invalid return URL. Domain not in allowed list.')
  }

  const intent: OAuthIntent = {
    returnUrl,
    provider,
    timestamp: Date.now(),
  }

  try {
    localStorage.setItem('oauth_intent', JSON.stringify(intent))
    console.log('Stored OAuth intent:', intent)
  } catch (e) {
    throw new Error('Failed to store OAuth intent. localStorage may be disabled.')
  }
}

// Retrieve and validate OAuth intent
function getOAuthIntent(): OAuthIntent | null {
  const stored = localStorage.getItem('oauth_intent')
  if (!stored) return null

  try {
    const data: OAuthIntent = JSON.parse(stored)
    const age = Date.now() - data.timestamp

    // Expire after 10 minutes
    if (age > 10 * 60 * 1000) {
      console.warn('OAuth intent expired')
      localStorage.removeItem('oauth_intent')
      return null
    }

    return data
  } catch {
    localStorage.removeItem('oauth_intent')
    return null
  }
}

// Build OAuth authorization URL
async function buildAuthUrl(provider: 'google' | 'apple'): Promise<string> {
  const { codeChallenge } = await setupPKCE()
  const state = generateState()

  const identityProvider = provider === 'google' ? 'Google' : 'SignInWithApple'

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: COGNITO_CONFIG.clientId,
    redirect_uri: COGNITO_CONFIG.redirectUri,
    identity_provider: identityProvider,
    scope: 'openid email profile',
    state: state,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
  })

  // Add prompt for Google to allow account selection
  if (provider === 'google') {
    params.append('prompt', 'select_account')
  }

  return `${COGNITO_CONFIG.domain}/oauth2/authorize?${params.toString()}`
}

// UI Helper functions
function showLoading(message: string): void {
  const content = document.getElementById('content')
  if (!content) return

  content.innerHTML = `
    <div class="status-container">
      <div class="spinner"></div>
      <h2>${message}</h2>
    </div>
  `
}

function showError(message: string, details?: string): void {
  const content = document.getElementById('content')
  if (!content) return

  content.innerHTML = `
    <div class="status-container error">
      <div class="error-icon">�</div>
      <h2>Authentication Error</h2>
      <p class="error-message">${message}</p>
      ${details ? `<p class="error-details">${details}</p>` : ''}
      <button onclick="window.location.href='https://cals-api.com'" class="btn">
        Return to Home
      </button>
    </div>
  `
}

// Main OAuth flow handler
async function handleOAuthFlow(): Promise<void> {
  const params = new URLSearchParams(window.location.search)

  // CASE 1: Incoming request with return_url and provider
  if (params.has('return_url') && params.has('provider')) {
    const returnUrl = params.get('return_url')!
    const provider = params.get('provider')!.toLowerCase()

    if (provider !== 'google' && provider !== 'apple') {
      showError('Invalid provider', 'Only "google" and "apple" are supported.')
      return
    }

    showLoading(`Redirecting to ${provider === 'google' ? 'Google' : 'Apple'}...`)

    try {
      // Validate and store intent
      storeOAuthIntent(returnUrl, provider as 'google' | 'apple')

      // Build auth URL and redirect
      const authUrl = await buildAuthUrl(provider as 'google' | 'apple')
      console.log('Redirecting to:', authUrl)

      // Small delay to show the loading state
      setTimeout(() => {
        window.location.href = authUrl
      }, 500)
    } catch (error) {
      console.error('Failed to initiate OAuth:', error)
      showError(
        'Failed to start authentication',
        error instanceof Error ? error.message : 'Unknown error'
      )
    }
    return
  }

  // CASE 2: OAuth callback with code
  if (params.has('code')) {
    showLoading('Completing authentication...')

    const code = params.get('code')!
    const state = params.get('state')
    const error = params.get('error')
    const errorDescription = params.get('error_description')

    // Check for OAuth errors
    if (error) {
      showError('OAuth provider error', errorDescription || error)
      return
    }

    // Validate state (CSRF protection)
    const storedState = sessionStorage.getItem('oauth_state')
    sessionStorage.removeItem('oauth_state')

    if (!state || !storedState || state !== storedState) {
      showError('Security validation failed', 'Invalid state parameter. Please try again.')
      return
    }

    // Get the stored intent
    const intent = getOAuthIntent()
    if (!intent) {
      showError('Session expired', 'OAuth session was not found or has expired.')
      return
    }

    // Clean up
    localStorage.removeItem('oauth_intent')
    sessionStorage.removeItem('pkce_code_verifier')

    // Build return URL with all OAuth parameters
    const returnUrl = new URL(intent.returnUrl)
    params.forEach((value, key) => {
      returnUrl.searchParams.set(key, value)
    })

    console.log('Redirecting to:', returnUrl.toString())

    // Redirect to original destination with OAuth params
    setTimeout(() => {
      window.location.href = returnUrl.toString()
    }, 500)
    return
  }

  // CASE 3: OAuth error callback
  if (params.has('error')) {
    const error = params.get('error')!
    const errorDescription = params.get('error_description')

    // Try to get return URL to redirect back with error
    const intent = getOAuthIntent()
    if (intent) {
      localStorage.removeItem('oauth_intent')
      const returnUrl = new URL(intent.returnUrl)
      returnUrl.searchParams.set('error', error)
      if (errorDescription) {
        returnUrl.searchParams.set('error_description', errorDescription)
      }
      window.location.href = returnUrl.toString()
      return
    }

    showError('Authentication failed', errorDescription || error)
    return
  }

  // CASE 4: Invalid request - show instructions
  const content = document.getElementById('content')
  if (!content) return

  content.innerHTML = `
    <div class="status-container">
      <h1>OAuth Redirect Service</h1>
      <p>This service handles OAuth authentication flows for multiple domains.</p>

      <h3>Usage:</h3>
      <p>Redirect users to:</p>
      <code>https://oauth.cals-api.com?return_url=YOUR_URL&provider=google</code>
      <p>or</p>
      <code>https://oauth.cals-api.com?return_url=YOUR_URL&provider=apple</code>

      <h3>Allowed Domains:</h3>
      <ul>
        ${ALLOWED_DOMAINS.map((d) => `<li>${d}</li>`).join('')}
      </ul>
    </div>
  `
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  handleOAuthFlow().catch((error) => {
    console.error('Unexpected error:', error)
    showError('Unexpected error occurred', error instanceof Error ? error.message : 'Unknown error')
  })
})
