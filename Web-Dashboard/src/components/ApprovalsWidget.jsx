import '../styles/approvals.css'

export default function ApprovalsWidget({ data }) {
  return (
    <section className="card card-approvals-summary">
      <div className="card-header">
        <h3>Smart Contract Approvals</h3>
      </div>
      <div className="approvals-items">
        <div className="approval-row">
          <span className="approval-label">High-risk approvals</span>
          <span className="approval-value">{data?.highRiskApprovals || '—'}</span>
        </div>
        <div className="approval-row">
          <span className="approval-label">Medium-risk approvals</span>
          <span className="approval-value">{data?.mediumRiskApprovals || '—'}</span>
        </div>
        <div className="approval-row">
          <span className="approval-label">Low-risk approvals</span>
          <span className="approval-value">{data?.lowRiskApprovals || '—'}</span>
        </div>
      </div>
    </section>
  )
}
