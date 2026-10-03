import React from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import UploadLog from './pages/UploadLog.jsx'
import Simulation from './pages/Simulation.jsx'
import Incidents from './pages/Incidents.jsx'
import InvestigationLoader from './pages/Investigation.jsx'
import useBackend from './hooks/useBackend.js'

export default function App() {
  const { online, health } = useBackend()

  return (
    <Layout online={online} health={health}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<UploadLog online={online} />} />
        <Route path="/simulation" element={<Simulation online={online} />} />
        <Route path="/incidents" element={<Incidents online={online} />} />
        <Route path="/incidents/:incidentId" element={<InvestigationLoader online={online} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
