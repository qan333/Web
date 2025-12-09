// src/pages/WalletScoringPage.jsx
import SearchSection from '../components/SearchSection'
import HealthOverview from '../components/HealthOverview'
import PortfolioSummary from '../components/PortfolioSummary'
import ValueAtRisk from '../components/ValueAtRisk'
import FlaggedAssets from '../components/FlaggedAssets'
import ApprovalsWidget from '../components/ApprovalsWidget'

export default function WalletScoringPage({
  walletData,
  loading,
  defaultWalletAddress,
  onSearchWallet,
}) {
  return (
    <>
      <SearchSection
        onSearch={onSearchWallet}
        loading={loading}
        defaultWalletAddress={defaultWalletAddress}
      />

      <div className="content-wrapper">
        {/* Left Column */}
        <div className="left-column">
          <div className="tabs">
            <button className="tab-btn active">Wallet health</button>
            <button className="tab-btn">Toxic score</button>
          </div>
          <HealthOverview data={walletData} />
        </div>

        {/* Right Column */}
        <div className="right-column">
          <div className="cards-row">
            <PortfolioSummary data={walletData} />
            <ValueAtRisk data={walletData} />
          </div>

          <div className="cards-row">
            <FlaggedAssets data={walletData} />
            <ApprovalsWidget data={walletData} />
          </div>
        </div>
      </div>
    </>
  )
}
