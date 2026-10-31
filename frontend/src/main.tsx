import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/42dot-sans/wght.css'
import './index.css'
import { BrowserRouter } from 'react-router-dom'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
