// SearchSection.jsx
import { useEffect, useState } from 'react'
import '../styles/search.css'


export default function SearchSection({ onSearch, loading, defaultWalletAddress }) {
  const [walletAddress, setWalletAddress] = useState('')
  const [network, setNetwork] = useState('ethereum')

  // Khi connect ví xong, auto-fill vào ô search
  useEffect(() => {
    if (defaultWalletAddress) {
      setWalletAddress(defaultWalletAddress)
    }
  }, [defaultWalletAddress])

  const handleSearch = () => {
    onSearch(walletAddress, network)
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') handleSearch()
  }

  return (
    <section className="search-section">
      <div className="search-box-container">
        <div className="search-input-group">
          <svg className="search-icon" width="20" height="20" viewBox="0 0 20 20" fill="none">
            <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="2" />
            <path d="M14 14L19 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            className="wallet-input"s
            placeholder="Search by ETH address"
            value={walletAddress}
            onChange={(e) => setWalletAddress(e.target.value)}
            onKeyPress={handleKeyPress}
          />
          {/* <select
            className="network-select"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
          >
            <option value="ethereum">Ethereum network</option>
            <option value="bsc">BSC Network</option>
            <option value="polygon">Polygon Network</option>
          </select> */}
        </div>
        <button className="btn-search" onClick={handleSearch} disabled={loading}>
          {loading ? <span className="spinner"></span> : 'Search'}
        </button>
      </div>

      <div className="search-actions">
        <button className="action-btn" title="Add to Favorites">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path
              d="M10 1L12.39 8.26H20L13.81 12.46L16.2 19.74L10 15.54L3.8 19.74L6.19 12.46L0 8.26H7.61L10 1Z"
              stroke="currentColor"
              strokeWidth="1.5"
              fill="none"
            />
          </svg>
          Add to Favorites
        </button>
        <button className="action-btn" title="Subscribe to Alerts">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path
              d="M10 1C7.24 1 5 3.24 5 6V8.83C5 9.34 4.8 10.11 4.54 10.54L2.41 14.54C1.59 15.97 2.15 17.07 3.71 17.07H16.29C17.85 17.07 18.41 15.97 17.59 14.54L15.46 10.54C15.2 10.11 15 9.34 15 8.83V6C15 3.24 12.76 1 10 1Z"
              stroke="currentColor"
              strokeWidth="1.5"
              fill="none"
            />
            <path
              d="M12 17C12 18.66 11.1 20 10 20C8.9 20 8 18.66 8 17"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
          Subscribe to alerts
        </button>
      </div>
    </section>
  )
}
