import '../styles/tx-alert.css'

export default function AlertTrackerPage({ reports = [] }) {
  const hasReports = reports.length > 0

  const downloadJson = (report) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scamradar-report-${report.address}-${report.id}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="content-wrapper">
      <section className="card card-alert-tracker">
        <div className="card-header">
          <h3>Report manager</h3>
          <p className="muted">
            Reports are saved locally in your browser (localStorage). Use them
            for your thesis / analysis.
          </p>
        </div>
        <div className="card-body">
          {!hasReports && <p>No reports saved yet.</p>}

          {hasReports && (
            <div className="report-table-wrapper">
              <table className="report-table">
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Created at</th>
                    <th>Total tx</th>
                    <th>In</th>
                    <th>Out</th>
                    <th>High risk</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.id}>
                      <td className="accent">{r.address}</td>
                      <td>{new Date(r.createdAt).toLocaleString()}</td>
                      <td>{r.totalTx}</td>
                      <td>{r.incoming}</td>
                      <td>{r.outgoing}</td>
                      <td>{r.highRisk}</td>
                      <td>{r.mediumRisk}</td>
                      <td>{r.lowRisk}</td>
                      <td>
                        <button
                          className="action-btn"
                          onClick={() => downloadJson(r)}
                        >
                          Download JSON
                        </button>
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
