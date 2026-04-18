// S11 — paywall with no Restore Purchases button
// S13 — hardcoded price while using Price API (getOfferings / price_ present)
import React from 'react';
import { Purchases } from '@revenuecat/purchases-capacitor';

export default function Paywall() {
  const handleSubscribe = async () => {
    const { offerings } = await Purchases.getOfferings();
    const pkg = offerings.current.monthly;
    await Purchases.purchasePackage({ aPackage: pkg });
  };

  return (
    <div className="paywall">
      <h1>Unlock Pro</h1>
      <div className="price">$9.99/month</div>
      <button onClick={handleSubscribe}>Subscribe</button>
    </div>
  );
}
