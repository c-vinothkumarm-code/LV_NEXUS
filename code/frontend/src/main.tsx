import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App'
import { AuthProvider } from './auth/AuthContext'
import { ToastProvider } from './components/Toast'
import { BRAND } from './theme/brand'
import { initTheme } from './theme/theme'

// Theme preference only (no credentials or tokens are ever stored in the browser). Follows the OS until the user picks one.
initTheme()
document.title = `${BRAND.product} · ${BRAND.company}`

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
)
