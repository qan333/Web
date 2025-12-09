import { useEffect, useState } from 'react'
import { fetchAccountTransactions } from '../services/api'
import '../styles/tx-alert.css'

/**
 * Props:
 *  - currentAddress: ví hiện tại
 *  - cachedTx: object cache từ App (key: `${address}-${page}`)
 *  - onCacheTx(address, page, txs): callback để lưu cache lên App
 *  - onCreateReport(report): lưu report cho AlertTracker
 */
export default function TransactionMonitorPage({
  currentAddress,
  cachedTx = {},
  onCacheTx,
  onCreateReport,
}) {
  const [txs, setTxs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(1)

  // Đổi ví thì reset về page 1
  useEffect(() => {
    setPage(1)
  }, [currentAddress])

  useEffect(() => {
    if (!currentAddress) return

    const key = `${currentAddress}-${page}`
    const cached = cachedTx[key]

    // Nếu đã có cache cho ví + page này → dùng luôn
    if (cached) {
      setTxs(cached)
      setError(null)
      return
    }

    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await fetchAccountTransactions(currentAddress, {
          page,
          limit: 50,
        })

        const list = data.transactions || data || []
        setTxs(list)
        onCacheTx?.(currentAddress, page, list)
      } catch (err) {
        console.error(err)
        const msg = (err.message || '').toLowerCase()
        if (msg.includes('no transactions found')) {
          setTxs([])
          setError(null)
        } else {
          setError('Failed to load transactions.')
        }
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [currentAddress, page]) // <-- chỉ phụ thuộc address + page


  const handleCreateReport = () => {
    if (!currentAddress || !txs.length || !onCreateReport) return

    const withRisk = txs.filter((tx) => typeof tx.risk_score === 'number')

    const report = {
      id: Date.now(),
      address: currentAddress,
      createdAt: new Date().toISOString(),
      totalTx: txs.length,
      incoming: txs.filter((tx) => tx.direction === 'in').length,
      outgoing: txs.filter((tx) => tx.direction === 'out').length,
      highRisk: withRisk.filter((tx) => tx.risk_score >= 0.7).length,
      mediumRisk: withRisk.filter(
        (tx) => tx.risk_score >= 0.3 && tx.risk_score < 0.7
      ).length,
      lowRisk: withRisk.filter((tx) => tx.risk_score < 0.3).length,
    }

    onCreateReport(report)
  }

  const shortHash = (h) => (h ? `${h.slice(0, 6)}...${h.slice(-4)}` : '')
  const formatDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '-')
  const formatEth = (v) => (v == null ? '-' : Number(v).toFixed(4))

  if (!currentAddress) {
    return (
      <div className="content-wrapper">
        <section className="card card-transaction-monitor">
          <div className="card-header">
            <h3>Transaction monitor</h3>
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
            <h3>Transaction monitor</h3>
            <p className="muted">
              Address: <span className="accent">{currentAddress}</span>
            </p>
          </div>

          <div className="tx-actions">
            <button
              className="action-btn"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
            >
              Prev
            </button>
            <span className="tx-page-label">Page {page}</span>
            <button
              className="action-btn"
              onClick={() => setPage((p) => p + 1)}
              disabled={loading}
            >
              Next
            </button>

            <button
              className="btn-search"
              onClick={handleCreateReport}
              disabled={!txs.length}
            >
              Save report
            </button>
          </div>
        </div>

        <div className="card-body">
          {loading && <p>Loading transactions...</p>}
          {error && <p className="text-error">{error}</p>}

          {!loading && !error && !txs.length && (
            <p>No transactions found for this wallet.</p>
          )}

          {!!txs.length && (
            <div className="tx-table-wrapper">
              <table className="tx-table">
                <thead>
                  <tr>
                    <th>Hash</th>
                    <th>Time</th>
                    <th>Direction</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Value (ETH)</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {txs.map((tx) => (
                    <tr key={tx.hash}>
                      <td title={tx.hash}>{shortHash(tx.hash)}</td>
                      <td>{formatDate(tx.timestamp)}</td>
                      <td
                        className={
                          tx.direction === 'out' ? 'tx-out' : 'tx-in'
                        }
                      >
                        {tx.direction === 'out' ? 'Outgoing' : 'Incoming'}
                      </td>
                      <td title={tx.from}>{shortHash(tx.from)}</td>
                      <td title={tx.to}>{shortHash(tx.to)}</td>
                      <td>{formatEth(tx.value_eth)}</td>
                      <td>
                        {typeof tx.risk_score === 'number'
                          ? `${(tx.risk_score * 100).toFixed(1)}%`
                          : '—'}
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
