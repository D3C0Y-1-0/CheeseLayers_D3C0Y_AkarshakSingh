import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

// Separate bundles: the dashboard never loads three.js, and the landing page never loads the charts.
const Landing = lazy(() => import('./landing/Landing'))
const Shell = lazy(() => import('./dashboard/Shell'))
const CommandCenter = lazy(() => import('./dashboard/CommandCenter'))
const Threats = lazy(() => import('./dashboard/Threats'))
const Assets = lazy(() => import('./dashboard/Assets'))
const Incidents = lazy(() => import('./dashboard/Incidents'))
const Incident = lazy(() => import('./dashboard/Incident'))
const Signals = lazy(() => import('./dashboard/Signals'))
const Analytics = lazy(() => import('./dashboard/Analytics'))

export default function App() {
  return (
    <Suspense fallback={null}>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/app" element={<Shell />}>
          <Route index element={<CommandCenter />} />
          <Route path="threats" element={<Threats />} />
          <Route path="assets" element={<Assets />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<Incident />} />
          <Route path="signals" element={<Signals />} />
          <Route path="analytics" element={<Analytics />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  )
}
