import '../styles/cards.css'

export default function ValueAtRisk({ data }) {
  const formatNumber = (num) => {
    if (!num) return '0.00'
    return Math.abs(num) >= 1000000
      ? (Math.abs(num) / 1000000).toFixed(2) + 'M'
      : Math.abs(num) >= 1000
      ? (Math.abs(num) / 1000).toFixed(2) + 'K'
      : num.toFixed(2)
  }

  return (
    <section className="card card-value-at-risk">
      <div className="card-header">
        <h3>Value at risk</h3>
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5" />
          <path d="M8 5V11M8 11L5 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>
      <div className="risk-value">
        <span className="currency">${formatNumber(data?.valueAtRisk || 0)}</span>
      </div>
      <div className="risk-items">
        <div className="risk-item">
          <span className="item-label">High-risk approvals</span>
          <span className="item-value">{data?.highRiskApprovals || '—'}</span>
        </div>
        <div className="risk-item">
          <span className="item-label">Medium-risk approvals</span>
          <span className="item-value">{data?.mediumRiskApprovals || '—'}</span>
        </div>
      </div>
    </section>
  )
}
