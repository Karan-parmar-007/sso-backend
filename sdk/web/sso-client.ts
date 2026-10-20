/**
 * Browser client for the karanparmar.in SSO.
 *
 * VENDORED FILE — source of truth: sso-backend/sdk/web/sso-client.ts.
 * Do not edit copies inside app repos; change it there and run `sdk/sync.sh`.
 *
 * Every app host routes `/api/auth/*` to the SSO backend (Caddy in prod,
 * the Vite proxy in dev), so these calls are same-origin and the browser
 * sends the refresh cookie (Path=/api/auth). `GET /api/auth/session`
 * therefore refreshes an expired access token server-side: a signed-in user
 * is never shown as signed out, and anonymous visitors cost one request.
 */

export interface SsoUser {
  id: string
  name: string
  email: string
  email_verified: boolean
  /** Global SSO role: owner | super_admin | user | custom */
  role_name: string | null
  /** App-scoped roles, e.g. { familyos: ['admin'] } */
  app_roles: Record<string, string[]>
  created_at?: string | null
  updated_at?: string | null
}

export interface SsoSession {
  authenticated: boolean
  user: SsoUser | null
  session_id: string | null
}

export interface SsoClientOptions {
  /** Public URL of the SSO frontend, e.g. https://auth.karanparmar.in, or ":5173" locally */
  ssoUrl: string
  /** Origin serving /api/auth (default: same origin). */
  apiBase?: string
  /** Origin used to build ?next= return URLs (default: window.location.origin). */
  appOrigin?: string
  fetch?: typeof fetch
}

export class SsoNetworkError extends Error {
  constructor(message = 'Unable to reach the sign-in service', cause?: unknown) {
    super(message, { cause })
    this.name = 'SsoNetworkError'
  }
}

export const ANONYMOUS: SsoSession = Object.freeze({
  authenticated: false,
  user: null,
  session_id: null,
}) as SsoSession

const CSRF_HEADER = 'X-CSRF-Token'
const CHANNEL = 'karanparmar-sso'

type SessionEvent = { type: 'login' | 'logout' | 'changed'; sessionId: string | null }

/**
 * Cross-app URLs may be configured as just a port (":5173") for local dev:
 * that means "this port on the host the page was opened from", so the same
 * build works on localhost and on a LAN/Tailscale IP (cookies are per host,
 * so every app must stay on one host). Absolute URLs pass through unchanged.
 */
export function resolveAppUrl(url: string): string {
  const value = url.trim().replace(/\/+$/, '')
  if (!/^:\d+$/.test(value)) return value
  if (typeof window === 'undefined') return `http://localhost${value}`
  return `${window.location.protocol}//${window.location.hostname}${value}`
}

export function readCsrfToken(): string | null {
  if (typeof document === 'undefined') return null
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)
  return match?.[1] ? decodeURIComponent(match[1]) : null
}

export function createSsoClient(options: SsoClientOptions) {
  const doFetch = (...args: Parameters<typeof fetch>) => (options.fetch ?? fetch)(...args)
  const apiBase = (options.apiBase ?? '').replace(/\/+$/, '')
  // Resolved on use: a port-only URL depends on the page's current host.
  const ssoUrl = () => resolveAppUrl(options.ssoUrl)

  let inflight: Promise<SsoSession> | null = null
  let lastSessionId: string | null | undefined
  const listeners = new Set<(session: SsoSession) => void>()

  const channel =
    typeof window !== 'undefined' && 'BroadcastChannel' in window
      ? new BroadcastChannel(CHANNEL)
      : null

  function appOrigin(): string {
    if (options.appOrigin) return resolveAppUrl(options.appOrigin)
    return typeof window !== 'undefined' ? window.location.origin : ''
  }

  function emit(session: SsoSession) {
    for (const listener of listeners) listener(session)
  }

  function broadcast(event: SessionEvent) {
    channel?.postMessage(event)
  }

  function track(session: SsoSession) {
    const sid = session.authenticated ? session.session_id : null
    if (lastSessionId !== undefined && sid !== lastSessionId) {
      broadcast({ type: sid ? 'login' : 'logout', sessionId: sid })
      emit(session)
    }
    lastSessionId = sid
  }

  async function fetchSession(): Promise<SsoSession> {
    let res: Response
    try {
      res = await doFetch(`${apiBase}/api/auth/session`, {
        method: 'GET',
        credentials: 'include',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      })
    } catch (cause) {
      throw new SsoNetworkError(undefined, cause)
    }
    if (!res.ok) {
      // /session is always 200 by contract; anything else = service trouble.
      throw new SsoNetworkError(`Sign-in service returned ${res.status}`)
    }
    const body = (await res.json()) as Partial<SsoSession>
    const session: SsoSession = body.authenticated
      ? {
          authenticated: true,
          user: (body.user ?? null) as SsoUser | null,
          session_id: body.session_id ?? null,
        }
      : ANONYMOUS
    track(session)
    return session
  }

  /**
   * Current session; refreshes server-side when needed. Concurrent callers
   * share one request (the refresh token rotates, so parallel refreshes
   * would race).
   */
  function getSession(): Promise<SsoSession> {
    if (!inflight) {
      inflight = fetchSession().finally(() => {
        inflight = null
      })
    }
    return inflight
  }

  /** After an app API 401: refresh the session, true if still signed in. */
  async function refresh(): Promise<boolean> {
    const session = await getSession()
    return session.authenticated
  }

  function returnUrl(returnTo?: string): string {
    if (returnTo && /^https?:\/\//i.test(returnTo)) return returnTo
    if (returnTo) {
      return `${appOrigin()}${returnTo.startsWith('/') ? returnTo : `/${returnTo}`}`
    }
    if (typeof window === 'undefined') return `${appOrigin()}/`
    const { pathname, search, hash } = window.location
    return `${appOrigin()}${pathname}${search}${hash}`
  }

  function ssoPage(path: string, returnTo?: string): string {
    const url = new URL(path, `${ssoUrl()}/`)
    url.searchParams.set('next', returnUrl(returnTo))
    return url.toString()
  }

  /** SSO login page; comes back to `returnTo` (path or absolute URL; default: here). */
  function loginUrl(returnTo?: string): string {
    return ssoPage('/login', returnTo)
  }

  function signupUrl(returnTo?: string): string {
    return ssoPage('/signup', returnTo)
  }

  function accountUrl(): string {
    return `${ssoUrl()}/account`
  }

  function redirectToLogin(returnTo?: string): void {
    if (typeof window !== 'undefined') window.location.assign(loginUrl(returnTo))
  }

  /**
   * End this session (or every session) in SSO. Works even when the access
   * token has expired. Other tabs are notified.
   */
  async function logout(opts: { everywhere?: boolean } = {}): Promise<void> {
    const headers: Record<string, string> = {}
    const csrf = readCsrfToken()
    if (csrf) headers[CSRF_HEADER] = csrf
    const query = opts.everywhere ? '?everywhere=true' : ''
    try {
      await doFetch(`${apiBase}/api/auth/logout${query}`, {
        method: 'POST',
        credentials: 'include',
        headers,
      })
    } finally {
      lastSessionId = null
      broadcast({ type: 'logout', sessionId: null })
      emit(ANONYMOUS)
    }
  }

  /**
   * Called when another tab logs in/out, or this tab notices the session
   * changed. Use it to invalidate cached user data.
   */
  function onSessionChange(listener: (session: SsoSession) => void): () => void {
    listeners.add(listener)
    return () => listeners.delete(listener)
  }

  if (channel) {
    channel.onmessage = (event: MessageEvent<SessionEvent>) => {
      if (event.data.type === 'logout') {
        lastSessionId = null
        emit(ANONYMOUS)
      } else {
        void getSession().then(emit, () => undefined)
      }
    }
  }

  return {
    getSession,
    refresh,
    loginUrl,
    signupUrl,
    accountUrl,
    redirectToLogin,
    logout,
    onSessionChange,
    csrfToken: readCsrfToken,
  }
}

export type SsoClient = ReturnType<typeof createSsoClient>

/** Global role helpers (mirror karan_sso.SsoIdentity). */
export function isOwner(user: SsoUser | null | undefined): boolean {
  return user?.role_name === 'owner'
}

export function isGlobalAdmin(user: SsoUser | null | undefined): boolean {
  return user?.role_name === 'owner' || user?.role_name === 'super_admin'
}

export function hasAppRole(user: SsoUser | null | undefined, app: string, role: string): boolean {
  return Boolean(user?.app_roles?.[app]?.includes(role))
}

/** Global owner/super_admin, or `admin` in this app. */
export function isAppAdmin(user: SsoUser | null | undefined, app: string): boolean {
  return isGlobalAdmin(user) || hasAppRole(user, app, 'admin')
}
