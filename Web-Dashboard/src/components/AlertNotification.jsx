export default function AlertNotification({ message, type }) {
  const bgColor = {
    success: 'var(--success-color)',
    warning: 'var(--warning-color)',
    danger: 'var(--danger-color)',
    info: 'var(--info-color)'
  }[type] || 'var(--info-color)'

  return (
    <div
      style={{
        position: 'fixed',
        top: '20px',
        right: '20px',
        padding: '1rem 1.5rem',
        background: bgColor,
        color: 'white',
        borderRadius: '8px',
        zIndex: 10000,
        fontWeight: 500,
        animation: 'slideIn 0.3s ease',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
      }}
    >
      {message}
    </div>
  )
}
