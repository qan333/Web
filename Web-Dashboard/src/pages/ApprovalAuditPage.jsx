// src/pages/ApprovalAuditPage.jsx
import { useEffect, useState } from 'react'
import { fetchAccountApprovals } from '../services/api'
import '../styles/tx-alert.css'   // dùng chung style card + table

export default function ApprovalAuditPage({ currentAddress }) {
  const [approvals, setApprovals] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Khi đổi ví ⇒ load lại approvals
  useEffect(() => {
    if (!currentAddress) {
      setApprovals([])
      setError(null)
      return
    }

    let cancelled = false

    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await fetchAccountApprovals(currentAddress)

        // chấp nhận 2 kiểu response: { approvals: [...] } hoặc [...]
        const list = data.approvals || data || []
        if (!cancelled) {
          setApprovals(list)
        }
      } catch (err) {
        console.error(err)
        if (!cancelled) {
          setError('Failed to load approvals.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    load()
    return () => { cancelled = true }
  }, [currentAddress])

  const formatAmount = (v) => {
    if (v == null) return '—'
    // nếu backend đã gửi allowance_human thì dùng; còn không parse number thường
    if (typeof v === 'string') {
      const n = Number(v)
      if (Number.isNaN(n)) return v
      return n.toLocaleString(undefined, { maximumFractionDigits: 4 })
    }
    return v.toLocaleString(undefined, { maximumFractionDigits: 4 })
  }

  const formatRiskLabel = (score, explicitLevel) => {
    if (explicitLevel) return explicitLevel.toUpperCase()
    if (typeof score !== 'number') return 'N/A'
    if (score >= 0.7) return 'HIGH'
    if (score >= 0.3) return 'MEDIUM'
    return 'LOW'
  }

  const riskClass = (score, explicitLevel) => {
    const lvl = explicitLevel || (
      typeof score === 'number'
        ? (score >= 0.7 ? 'high' : score >= 0.3 ? 'medium' : 'low')
        : 'unknown'
    )

    switch (lvl.toLowerCase()) {
      case 'high': return 'tx-out'
      case 'medium': return 'muted'
      case 'low': return 'tx-in'
      default: return ''
    }
  }

  if (!currentAddress) {
    return (
      <div className="content-wrapper">
        <section className="card card-transaction-monitor">
          <div className="card-header">
            <h3>Approval audit</h3>
          </div>
          <div className="card-body">
            <p>
              No wallet selected. Please connect a wallet or analyze a wallet on
              the <strong>Wallet scoring</strong> page first.
            </p>
          </div>
        </section>
      </div>
    )
  }

  return (
    <div className="content-wrapper">
      <section className="card card-transaction-monitor">
        <div className="card-header tx-card-header">
          <div>
            <h3>Approval audit</h3>
            <p className="muted">
              Address: <span className="accent">{currentAddress}</span>
            </p>
          </div>
        </div>

        <div className="card-body">
          {loading && <p>Loading approvals...</p>}
          {error && <p className="text-error">{error}</p>}

          {!loading && !error && !approvals.length && (
            <p>No approvals found for this wallet.</p>
          )}

          {!!approvals.length && (
            <div className="tx-table-wrapper">
              <table className="tx-table">
                <thead>
                  <tr>
                    <th>Token</th>
                    <th>Spender</th>
                    <th>Allowance</th>
                    <th>Type</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {approvals.map((appr, idx) => (
                    <tr key={appr.id || appr.tx_hash || idx}>
                      <td>
                        <div>
                          <strong>{appr.token_symbol || 'Unknown'}</strong>
                        </div>
                        <div className="muted" title={appr.token_address}>
                          {appr.token_address
                            ? `${appr.token_address.slice(0, 6)}...${appr.token_address.slice(-4)}`
                            : '—'}
                        </div>
                      </td>
                      <td title={appr.spender}>
                        {appr.spender
                          ? `${appr.spender.slice(0, 6)}...${appr.spender.slice(-4)}`
                          : '—'}
                      </td>
                      <td>{formatAmount(appr.allowance_human ?? appr.allowance)}</td>
                      <td>{appr.tx_type || appr.token_type || 'ERC20'}</td>
                      <td className={riskClass(appr.risk_score, appr.risk_level)}>
                        {formatRiskLabel(appr.risk_score, appr.risk_level)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
