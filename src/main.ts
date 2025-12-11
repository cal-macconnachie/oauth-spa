/**
 * OAuth Redirect SPA
 * Handles OAuth flows for multiple domains without redeploying infrastructure
 */

// Configuration
const COGNITO_CONFIG = {
  region: 'us-east-1',
  devUserPoolId: 'us-east-1_c0hPAs0Us',
  prodUserPoolId: 'us-east-1_QA3w6mkCV',
  devClientId: '37u4esg6blk7sdbqvjhlbjh3hk',
  prodClientId: '7l7un286e3nm1r1jb2ubuu7nim',
  devDomain: 'https://auth.dev.marketplace.csm.codes',
  prodDomain: 'https://auth.marketplace.csm.codes',
}

// Determine environment based on current hostname
function getEnvironment(): 'dev' | 'prod' {
  const hostname = window.location.hostname
  return hostname.includes('dev.oauth') ? 'dev' : 'prod'
}

// Get environment-specific config values
function getClientId(): string {
  return getEnvironment() === 'dev' ? COGNITO_CONFIG.devClientId : COGNITO_CONFIG.prodClientId
}

function getCognitoDomain(): string {
  return getEnvironment() === 'dev' ? COGNITO_CONFIG.devDomain : COGNITO_CONFIG.prodDomain
}

function getRedirectUri(): string {
  const env = getEnvironment()
  return env === 'dev'
    ? 'https://dev.oauth.cals-api.com/auth/callback'
    : 'https://oauth.cals-api.com/auth/callback'
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
  theme?: 'light' | 'dark'
}

// Logout intent stored in localStorage
interface LogoutIntent {
  returnUrl: string
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

// Store logout intent before showing logout confirmation
function storeLogoutIntent(returnUrl: string): void {
  if (!validateReturnUrl(returnUrl)) {
    throw new Error('Invalid return URL. Domain not in allowed list.')
  }

  const intent: LogoutIntent = {
    returnUrl,
    timestamp: Date.now(),
  }

  try {
    localStorage.setItem('logout_intent', JSON.stringify(intent))
    console.log('Stored logout intent:', intent)
  } catch (e) {
    throw new Error('Failed to store logout intent. localStorage may be disabled.')
  }
}

// Retrieve and validate logout intent
function getLogoutIntent(): LogoutIntent | null {
  const stored = localStorage.getItem('logout_intent')
  if (!stored) return null

  try {
    const data: LogoutIntent = JSON.parse(stored)
    const age = Date.now() - data.timestamp

    // Expire after 10 minutes
    if (age > 10 * 60 * 1000) {
      console.warn('Logout intent expired')
      localStorage.removeItem('logout_intent')
      return null
    }

    return data
  } catch {
    localStorage.removeItem('logout_intent')
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
    client_id: getClientId(),
    redirect_uri: getRedirectUri(),
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

  return `${getCognitoDomain()}/oauth2/authorize?${params.toString()}`
}

// Provider SVG icons
const PROVIDER_ICONS = {
  google: `
    <svg viewBox="-0.5 0 48 48" width="48" height="48" fill="none">
      <path d="M9.82727273,24 C9.82727273,22.4757333 10.0804318,21.0144 10.5322727,19.6437333 L2.62345455,13.6042667 C1.08206818,16.7338667 0.213636364,20.2602667 0.213636364,24 C0.213636364,27.7365333 1.081,31.2608 2.62025,34.3882667 L10.5247955,28.3370667 C10.0772273,26.9728 9.82727273,25.5168 9.82727273,24" fill="#FBBC05"></path>
      <path d="M23.7136364,10.1333333 C27.025,10.1333333 30.0159091,11.3066667 32.3659091,13.2266667 L39.2022727,6.4 C35.0363636,2.77333333 29.6954545,0.533333333 23.7136364,0.533333333 C14.4268636,0.533333333 6.44540909,5.84426667 2.62345455,13.6042667 L10.5322727,19.6437333 C12.3545909,14.112 17.5491591,10.1333333 23.7136364,10.1333333" fill="#EB4335"></path>
      <path d="M23.7136364,37.8666667 C17.5491591,37.8666667 12.3545909,33.888 10.5322727,28.3562667 L2.62345455,34.3946667 C6.44540909,42.1557333 14.4268636,47.4666667 23.7136364,47.4666667 C29.4455,47.4666667 34.9177955,45.4314667 39.0249545,41.6181333 L31.5177727,35.8144 C29.3995682,37.1488 26.7323182,37.8666667 23.7136364,37.8666667" fill="#34A853"></path>
      <path d="M46.1454545,24 C46.1454545,22.6133333 45.9318182,21.12 45.6113636,19.7333333 L23.7136364,19.7333333 L23.7136364,28.8 L36.3181818,28.8 C35.6879545,31.8912 33.9724545,34.2677333 31.5177727,35.8144 L39.0249545,41.6181333 C43.3393409,37.6138667 46.1454545,31.6490667 46.1454545,24" fill="#4285F4"></path>
    </svg>
  `,
  apple: `
    <svg viewBox="-3.5 0 48 48" width="48" height="48">
      <path d="M231.174735,567.792499 C232.740177,565.771699 233.926883,562.915484 233.497649,560 C230.939077,560.177808 227.948466,561.814769 226.203475,563.948463 C224.612784,565.88177 223.305444,568.757742 223.816036,571.549042 C226.613071,571.636535 229.499881,569.960061 231.174735,567.792499 L231.174735,567.792499 Z M245,595.217241 C243.880625,597.712195 243.341978,598.827022 241.899976,601.03692 C239.888467,604.121745 237.052156,607.962958 233.53412,607.991182 C230.411652,608.02505 229.606488,605.94498 225.367451,605.970382 C221.128414,605.99296 220.244696,608.030695 217.116618,607.999649 C213.601387,607.968603 210.913765,604.502761 208.902256,601.417937 C203.27452,592.79849 202.68257,582.680377 206.152914,577.298162 C208.621711,573.476705 212.515678,571.241407 216.173986,571.241407 C219.89682,571.241407 222.239372,573.296075 225.322563,573.296075 C228.313175,573.296075 230.133913,571.235762 234.440281,571.235762 C237.700215,571.235762 241.153726,573.022307 243.611302,576.10431 C235.554045,580.546683 236.85858,592.121127 245,595.217241 L245,595.217241 Z" transform="translate(-204.000000, -560.000000)" fill="#0b0b0a"></path>
    </svg>
  `,
}

// UI Helper functions
function showLoading(message: string, icon?: string): void {
  const content = document.getElementById('content')
  if (!content) return

  content.innerHTML = `
    <div class="status-container">
      ${
        icon
          ? `<div class="provider-icon" style="display: flex; justify-content: center; align-items: center;">${icon}</div>`
          : '<div class="spinner"></div>'
      }
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

function showLogoutComplete(returnUrl: string): void {
  const content = document.getElementById('content')
  if (!content) return

  content.innerHTML = `
    <div class="status-container">
      <div class="success-icon">✓</div>
      <h2>Logged Out Successfully</h2>
      <p>You have been logged out. Redirecting you back...</p>
      <p class="redirect-note">You will be redirected in a moment.</p>
    </div>
  `

  // Redirect after a brief delay
  setTimeout(() => {
    window.location.href = returnUrl
  }, 1500)
}

// Main OAuth flow handler
async function handleOAuthFlow(): Promise<void> {
  const params = new URLSearchParams(window.location.search)
  const localStorageTheme = localStorage.getItem('oauth_theme')
  if (localStorageTheme === 'dark' || localStorageTheme === 'light') {
    document.body.dataset.theme = localStorageTheme
  }

  // CASE 0: Logout flow (from Cognito state parameter)
  // Cognito passes logout info via state parameter after logout
  const stateParam = params.get('state')
  if (stateParam) {
    try {
      const state = JSON.parse(stateParam)

      // Check if this is a logout flow
      if (state.logout === true && state.return_url) {
        const returnUrl = state.return_url

        // Validate return URL
        if (!validateReturnUrl(returnUrl)) {
          showError('Invalid return URL', 'The return URL domain is not in the allowed list.')
          return
        }

        // Store logout intent
        storeLogoutIntent(returnUrl)

        // Show logout completion message and redirect
        showLogoutComplete(returnUrl)
        return
      }
    } catch (error) {
      // If state parsing fails, it's not a logout flow - continue to other cases
      console.log('State parameter is not a logout flow:', error)
    }
  }

  // CASE 0b: Legacy logout flow with query parameters (for backwards compatibility)
  if (params.has('logout') && params.get('logout') === 'true') {
    const returnUrl = params.get('return_url')

    if (!returnUrl) {
      showError('Missing return URL', 'A return_url parameter is required for logout.')
      return
    }

    try {
      // Validate and store logout intent
      storeLogoutIntent(returnUrl)

      // Show logout completion message and redirect
      showLogoutComplete(returnUrl)
    } catch (error) {
      console.error('Failed to process logout:', error)
      showError(
        'Logout failed',
        error instanceof Error ? error.message : 'Unknown error'
      )
    }
    return
  }

  // CASE 1: Incoming request with return_url and provider
  if (params.has('return_url') && params.has('provider')) {
    const returnUrl = params.get('return_url')!
    const provider = params.get('provider')!.toLowerCase()
    const theme = params.get('theme')?.toLowerCase()
    if (theme) {
      document.body.dataset.theme = theme === 'dark' ? 'dark' : 'light'
      localStorage.setItem('oauth_theme', theme === 'dark' ? 'dark' : 'light')
    }

    if (provider !== 'google' && provider !== 'apple') {
      showError('Invalid provider', 'Only "google" and "apple" are supported.')
      return
    }

    const providerIcon = PROVIDER_ICONS[provider as 'google' | 'apple']
    showLoading(`Redirecting to ${provider === 'google' ? 'Google' : 'Apple'}...`, providerIcon)

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
    const providerIcon = intent ? PROVIDER_ICONS[intent.provider] : undefined
    showLoading('Completing authentication...', providerIcon)
    if (!intent) {
      showError('Session expired', 'OAuth session was not found or has expired.')
      return
    }

    // Get PKCE code verifier
    const codeVerifier = sessionStorage.getItem('pkce_code_verifier')
    if (!codeVerifier) {
      showError('Session error', 'PKCE verification failed. Please try again.')
      localStorage.removeItem('oauth_intent')
      return
    }

    // Exchange authorization code for tokens
    try {
      const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: getClientId(),
        code: code,
        redirect_uri: getRedirectUri(),
        code_verifier: codeVerifier,
      })

      const tokenResponse = await fetch(`${getCognitoDomain()}/oauth2/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: tokenParams.toString(),
      })

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json().catch(() => ({}))
        throw new Error(errorData.error_description || 'Token exchange failed')
      }

      const tokens = await tokenResponse.json()

      // Clean up
      localStorage.removeItem('oauth_intent')
      sessionStorage.removeItem('pkce_code_verifier')

      // Build return URL with tokens instead of code
      const returnUrl = new URL(intent.returnUrl)
      returnUrl.searchParams.set('access_token', tokens.access_token)
      returnUrl.searchParams.set('id_token', tokens.id_token)
      returnUrl.searchParams.set('refresh_token', tokens.refresh_token)
      returnUrl.searchParams.set('token_type', tokens.token_type || 'Bearer')
      if (tokens.expires_in) {
        returnUrl.searchParams.set('expires_in', tokens.expires_in.toString())
      }

      console.log('Redirecting to:', returnUrl.toString())

      // Redirect to original destination with tokens
      setTimeout(() => {
        window.location.href = returnUrl.toString()
      }, 500)
    } catch (error) {
      console.error('Token exchange failed:', error)
      showError(
        'Authentication failed',
        error instanceof Error ? error.message : 'Failed to exchange authorization code for tokens'
      )
      // Clean up on error
      localStorage.removeItem('oauth_intent')
      sessionStorage.removeItem('pkce_code_verifier')
    }
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
