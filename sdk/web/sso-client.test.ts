import { describe, expect, it, vi } from 'vitest'
import { ANONYMOUS, SsoNetworkError, createSsoClient, isAppAdmin, resolveAppUrl } from './sso-client'

const user = {
  id: 'u1',
  name: 'U',
  email: 'u@example.com',
  email_verified: true,
  role_name: 'user',
  app_roles: { familyos: ['admin'] },
}

function client(responses: Array<Response | Error>) {
  const fetchMock = vi.fn(async () => {
    const next = responses.shift()
    if (!next) throw new Error('unexpected fetch')
    if (next instanceof Error) throw next
    return next
  })
  const sso = createSsoClient({
    ssoUrl: 'https://auth.example.com/',
    appOrigin: 'https://app.example.com',
    fetch: fetchMock as unknown as typeof fetch,
  })
  return { sso, fetchMock }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

describe('sso-client', () => {
  it('shares one /session request between concurrent callers', async () => {
    const { sso, fetchMock } = client([json({ authenticated: true, user, session_id: 's1' })])
    const [a, b] = await Promise.all([sso.getSession(), sso.getSession()])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(a).toBe(b)
    expect(a.user?.email).toBe('u@example.com')
  })

  it('maps anonymous responses to ANONYMOUS', async () => {
    const { sso } = client([json({ authenticated: false, user: null, session_id: null })])
    expect(await sso.getSession()).toBe(ANONYMOUS)
  })

  it('throws SsoNetworkError on network failure or non-200', async () => {
    const { sso } = client([new TypeError('Failed to fetch'), json({}, 502)])
    await expect(sso.getSession()).rejects.toBeInstanceOf(SsoNetworkError)
    await expect(sso.getSession()).rejects.toBeInstanceOf(SsoNetworkError)
  })

  it('builds login/signup URLs with an absolute next', () => {
    const { sso } = client([])
    const login = new URL(sso.loginUrl('/personal/dashboard?x=1#h'))
    expect(login.origin + login.pathname).toBe('https://auth.example.com/login')
    expect(login.searchParams.get('next')).toBe('https://app.example.com/personal/dashboard?x=1#h')
    expect(new URL(sso.signupUrl('dash')).searchParams.get('next')).toBe('https://app.example.com/dash')
  })

  it('logout posts to SSO and notifies listeners even if the request fails', async () => {
    const { sso, fetchMock } = client([new TypeError('Failed to fetch')])
    const seen: unknown[] = []
    sso.onSessionChange((s) => seen.push(s))
    await expect(sso.logout({ everywhere: true })).rejects.toThrow()
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/logout?everywhere=true', expect.objectContaining({ method: 'POST', credentials: 'include' }))
    expect(seen).toEqual([ANONYMOUS])
  })

  it('role helpers', () => {
    expect(isAppAdmin(user, 'familyos')).toBe(true)
    expect(isAppAdmin(user, 'portfolio')).toBe(false)
    expect(isAppAdmin({ ...user, role_name: 'super_admin', app_roles: {} }, 'portfolio')).toBe(true)
  })

  it('resolves port-only URLs against the current host', () => {
    expect(resolveAppUrl('https://auth.example.com/')).toBe('https://auth.example.com')
    expect(resolveAppUrl(':5173')).toBe('http://localhost:5173') // no window: SSR / node
    const original = globalThis.window
    ;(globalThis as { window?: unknown }).window = {
      location: { protocol: 'http:', hostname: '100.90.184.17' },
    }
    try {
      expect(resolveAppUrl(':5173')).toBe('http://100.90.184.17:5173')
      const { sso } = client([])
      expect(createSsoClient({ ssoUrl: ':5173', appOrigin: ':5175' }).loginUrl('/x')).toBe(
        'http://100.90.184.17:5173/login?next=http%3A%2F%2F100.90.184.17%3A5175%2Fx',
      )
      expect(sso).toBeDefined()
    } finally {
      ;(globalThis as { window?: unknown }).window = original
    }
  })
})
