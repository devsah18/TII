import React, { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { Empty } from './ui.jsx'

/**
 * Attack relationship graph. Nodes and edges come from the backend
 * (incident.attack_graph); cytoscape only renders them.
 */
const NODE_STYLE = {
  attacker: { fill: '#7f1d1d', border: '#ef4444', shape: 'hexagon', w: 74, h: 74 },
  compromised: { fill: '#7c2d12', border: '#f97316', shape: 'round-rectangle', w: 88, h: 60 },
  endpoint: { fill: '#1e3a8a', border: '#3b82f6', shape: 'round-rectangle', w: 92, h: 56 },
  privilege: { fill: '#78350f', border: '#fbbf24', shape: 'diamond', w: 80, h: 80 },
  resource: { fill: '#134e4a', border: '#14b8a6', shape: 'round-rectangle', w: 100, h: 58 },
  source: { fill: '#1e293b', border: '#64748b', shape: 'round-rectangle', w: 86, h: 56 },
  default: { fill: '#1e293b', border: '#64748b', shape: 'round-rectangle', w: 84, h: 54 },
}

function styleFor(type) {
  return NODE_STYLE[type] || NODE_STYLE.default
}

export default function AttackGraph({ graph }) {
  const ref = useRef(null)
  const cyRef = useRef(null)
  const [hovered, setHovered] = useState(null)

  const elements = useMemo(() => {
    if (!graph || !Array.isArray(graph.nodes)) return []
    const nodes = graph.nodes.map((n) => {
      const s = styleFor(n.type)
      return {
        data: {
          id: n.id,
          label: n.label,
          type: n.type,
          subtitle: n.subtitle || '',
          external: Boolean(n.external),
          suspicious: Boolean(n.suspicious),
          w: s.w,
          h: s.h,
        },
      }
    })
    const edges = (graph.edges || []).map((e) => ({
      data: { id: e.id, source: e.source, target: e.target, label: e.label, severity: e.severity },
    }))
    return [...nodes, ...edges]
  }, [graph])

  useEffect(() => {
    if (!ref.current) return undefined
    if (!elements.length) {
      if (cyRef.current) {
        cyRef.current.destroy()
        cyRef.current = null
      }
      return undefined
    }

    const cy = cytoscape({
      container: ref.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (el) => styleFor(el.data('type')).fill,
            'border-color': (el) => styleFor(el.data('type')).border,
            'border-width': 2,
            shape: (el) => styleFor(el.data('type')).shape,
            width: (el) => el.data('w'),
            height: (el) => el.data('h'),
            label: 'data(label)',
            color: '#e8eefb',
            'font-size': 11,
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '88px',
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.8,
            'line-color': (el) => (el.data('severity') === 'critical' ? '#ef4444' : el.data('severity') === 'high' ? '#f97316' : '#3f5675'),
            'target-arrow-color': (el) => (el.data('severity') === 'critical' ? '#ef4444' : el.data('severity') === 'high' ? '#f97316' : '#3f5675'),
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.85,
            'curve-style': 'bezier',
            'line-style': (el) => (el.data('severity') === 'critical' ? 'solid' : 'dashed'),
            label: 'data(label)',
            'font-size': 9,
            color: '#8fa2c0',
            'text-background-color': '#060a12',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
            'text-margin-y': -6,
          },
        },
        {
          selector: 'node:selected',
          style: { 'border-width': 3, 'border-color': '#e8eefb' },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.25,
        padding: 26,
        animate: false,
      },
      wheelSensitivity: 0.25,
      minZoom: 0.35,
      maxZoom: 2.4,
    })

    cy.on('mouseover', 'node', (evt) => setHovered({ node: evt.target.data() }))
    cy.on('mouseout', 'node', () => setHovered(null))

    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [elements])

  if (!elements.length) {
    return <Empty>The backend did not return graph nodes for this incident.</Empty>
  }

  return (
    <>
      <div className="graph-wrap" ref={ref} />
      <div className="graph-legend">
        {[
          ['attacker', 'Attacker / external IP'],
          ['compromised', 'Compromised identity'],
          ['endpoint', 'Endpoint / service'],
          ['privilege', 'Privileges obtained'],
          ['resource', 'Data store / resource'],
        ].map(([type, label]) => (
          <span key={type} className="legend-item">
            <span className="legend-swatch" style={{ background: styleFor(type).fill, border: `1.5px solid ${styleFor(type).border}` }} />
            {label}
          </span>
        ))}
      </div>
      {hovered && (
        <div className="card-note mt-8">
          <span className="mono">{hovered.node.label}</span>
          {hovered.node.subtitle ? ` — ${hovered.node.subtitle}` : ''} · node type:{' '}
          <span className="mono">{hovered.node.type}</span>
        </div>
      )}
    </>
  )
}
