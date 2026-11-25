/**
 * Theme preference: 'light' | 'dark' | 'system' (default). Stored with the existing application preference key
 * ('cn-theme'); only the preference name is stored, never anything else. 'system' follows the operating system setting
 * live. The resolved theme is applied as <html data-theme="light|dark">.
 */
export type ThemePref = 'light' | 'dark' | 'system'
const KEY = 'cn-theme'
const media = () => window.matchMedia('(prefers-color-scheme: dark)')

export function getThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY) ?? localStorage.getItem('mcp-theme')
    return v === 'light' || v === 'dark' ? v : 'system'
  } catch { return 'system' }
}

export function resolveTheme(pref: ThemePref): 'light' | 'dark' {
  return pref === 'system' ? (media().matches ? 'dark' : 'light') : pref
}

export function applyTheme(pref: ThemePref) {
  document.documentElement.dataset.theme = resolveTheme(pref)
  document.documentElement.dataset.themePref = pref
  window.dispatchEvent(new CustomEvent('cn-theme-change', { detail: resolveTheme(pref) }))
}

export function setThemePref(pref: ThemePref) {
  try { if (pref === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, pref) } catch { /* storage blocked */ }
  applyTheme(pref)
}

/** Call once at start-up: applies the preference and follows the OS while the preference is 'system'. */
export function initTheme() {
  applyTheme(getThemePref())
  media().addEventListener('change', () => { if (getThemePref() === 'system') applyTheme('system') })
}
