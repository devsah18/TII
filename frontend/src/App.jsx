import React, { useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import UploadLog from './pages/UploadLog.jsx'
import Simulation from './pages/Simulation.jsx'
import Incidents from './pages/Incidents.jsx'
import InvestigationLoader from './pages/Investigation.jsx'
import LiveCapturePage from './pages/LiveCapture.jsx'
import History from './pages/History.jsx'
import useBackend from './hooks/useBackend.js'
import { ToastProvider } from './components/Toast.jsx'
import CommandPalette from './components/CommandPalette.jsx'

export default function App() {
  const { online, health } = useBackend()
  const [cmdkOpen, setCmdkOpen] = useState(false)

  // Global Ctrl/Cmd + K opens the command palette.
  useEffect(() => {
    function onKey(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setCmdkOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <ToastProvider>
      <Layout online={online} health={health} onOpenPalette={() => setCmdkOpen(true)}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<UploadLog online={online} />} />
          <Route path="/simulation" element={<Simulation online={online} />} />
          <Route path="/live" element={<LiveCapturePage online={online} />} />
          <Route path="/incidents" element={<Incidents online={online} />} />
          <Route path="/history" element={<History online={online} />} />
          <Route path="/incidents/:incidentId" element={<InvestigationLoader online={online} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
      <CommandPalette open={cmdkOpen} onClose={() => setCmdkOpen(false)} />
    </ToastProvider>
  )
}
