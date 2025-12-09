// src/components/Sidebar.jsx
import { useState } from 'react'
import logoImage from '../assets/logo.png';
import '../styles/sidebar.css'

export default function Sidebar({ activePage, onChangePage }) {
  const [theme, setTheme] = useState(false)

  // CHÚ Ý: id phải trùng với các case trong App.jsx: wallet, approval, tx-monitor, alerts
  const navItems = [
    { id: 'wallet', label: 'Wallet scoring', icon: 'wallet' },
    { id: 'approval', label: 'Approval audit', icon: 'check' },
    { id: 'tx-monitor', label: 'Transaction monitor', icon: 'transaction' },
    { id: 'alerts', label: 'Alert tracker', icon: 'alert' }
  ]

  const footerItems = [
    { label: 'Onboarding', icon: 'onboarding' },
    { label: 'Dashboard wiki', icon: 'wiki' }
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="logo-box">
          <img 
            src={logoImage} 
            alt="Logo ScamRadar" 
            className="logo-icon" 
          />
        </div>
        <span className="sidebar-title">Scam Radar</span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-item ${activePage === item.id ? 'active' : ''}`}
            onClick={() => onChangePage(item.id)}
          >
            <SVGIcon icon={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        {footerItems.map((item, idx) => (
          <button
            key={idx}
            type="button"
            className="nav-item"
            onClick={() => {}}
          >
            <SVGIcon icon={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}

        <div className="theme-toggle">
          <span>Light mode</span>
          <button
            className={`toggle-switch ${theme ? 'active' : ''}`}
            onClick={() => setTheme(!theme)}
          >
            <span className="toggle-circle"></span>
          </button>
        </div>
      </div>
    </aside>
  )
}

function SVGIcon({ icon }) {
  const icons = {
    wallet: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <rect x="3" y="7" width="18" height="14" rx="2" stroke="currentColor" strokeWidth="2" />
        <path d="M7 7V5C7 3.89543 7.89543 3 9 3H15C16.1046 3 17 3.89543 17 5V7" stroke="currentColor" strokeWidth="2" />
      </svg>
    ),
    check: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
        <path d="M8 12L11 15L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
    transaction: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M12 2L22 7V17L12 22L2 17V7L12 2Z" stroke="currentColor" strokeWidth="2" />
      </svg>
    ),
    alert: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M12 2C6.48 2 2 6.48 2 12C2 17.52 6.48 22 12 22C17.52 22 22 17.52 22 12C22 6.48 17.52 2 12 2Z" stroke="currentColor" strokeWidth="2" />
        <circle cx="12" cy="16" r="1.5" fill="currentColor" />
        <path d="M12 8V13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
    onboarding: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M11 3H5C3.9 3 3 3.9 3 5V19C3 20.1 3.9 21 5 21H19C20.1 21 21 20.1 21 19V13" stroke="currentColor" strokeWidth="2" />
      </svg>
    ),
    wiki: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" />
        <path d="M12 6V12L16 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    )
  }
  return icons[icon] || null
}
