// src/components/Header.jsx
import '../styles/header.css'

export default function Header({
  onFavorite,
  onConnectWallet,
  walletAddress,
  pageTitle,
  pageSubtitle
}) {
  const shortAddr = (addr) =>
    addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : ''

  return (
    <header className="header">
      <div className="header-left">
        <h1>{pageTitle}</h1>
        <p>{pageSubtitle}</p>
      </div>
      <div className="header-right">
        <button
          className="btn-favorite"
          onClick={onFavorite}
          title="Add to Favorites"
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path
              d="M10 1L12.39 8.26H20L13.81 12.46L16.2 19.74L10 15.54L3.8 19.74L6.19 12.46L0 8.26H7.61L10 1Z"
              stroke="currentColor"
              strokeWidth="1.5"
              fill="none"
            />
          </svg>
          Favorites
        </button>

        <button
          className="btn-connect"
          onClick={onConnectWallet}
          title={walletAddress || 'Connect wallet'}
        >
          {walletAddress ? shortAddr(walletAddress) : 'Connect wallet'}
        </button>
      </div>
    </header>
  )
}
