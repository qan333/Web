import '../styles/flagged-assets.css'

export default function FlaggedAssets({ data }) {
  return (
    <section className="card card-flagged-assets">
      <div className="card-header">
        <h3>Flagged Assets</h3>
      </div>
      <div className="assets-list">
        <div className="asset-item">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="currentColor">
            <path d="M9 1L11 7H17L12 10L14 16L9 13L4 16L6 10L1 7H7L9 1Z" />
          </svg>
          <span>Flagged Tokens</span>
          <span className="count">{data?.riskyTokens || '—'}</span>
        </div>
        <div className="asset-item">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="currentColor">
            <path d="M9 2C5.14 2 2 5.14 2 9C2 12.86 5.14 16 9 16C12.86 16 16 12.86 16 9C16 5.14 12.86 2 9 2Z" />
          </svg>
          <span>Honeypot Tokens</span>
          <span className="count">{data?.honeypot || '—'}</span>
        </div>
        <div className="asset-item">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="currentColor">
            <path d="M9 2C5.14 2 2 5.14 2 9C2 12.86 5.14 16 9 16C12.86 16 16 12.86 16 9C16 5.14 12.86 2 9 2Z" />
          </svg>
          <span>Wash Traded</span>
          <span className="count">{data?.washTraded || '—'}</span>
        </div>
      </div>
    </section>
  )
}
