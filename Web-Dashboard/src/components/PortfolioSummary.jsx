import '../styles/cards.css'

export default function PortfolioSummary({ data }) {
  const formatNumber = (num) => {
    if (!num) return '0.00'
    return Math.abs(num) >= 1000000
      ? (Math.abs(num) / 1000000).toFixed(2) + 'M'
      : Math.abs(num) >= 1000
      ? (Math.abs(num) / 1000).toFixed(2) + 'K'
      : num.toFixed(2)
  }

  return (
    <section className="card card-portfolio-summary">
      <div className="card-header">
        <h3>Portfolio summary</h3>
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5" />
          <path d="M8 5V8L10.5 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>
      <div className="portfolio-value">
        <span className="currency">${formatNumber(data?.portfolioValue || 0)}</span>
      </div>
      <div className="portfolio-items">
        <div className="portfolio-item">
          <span className="item-label">Flagged Tokens</span>
          <span className="item-value">{data?.tokens || '—'}</span>
        </div>
        <div className="portfolio-item">
          <span className="item-label">Risky NFTs</span>
          <span className="item-value">{data?.nfts || '—'}</span>
        </div>
      </div>
    </section>
  )
}
