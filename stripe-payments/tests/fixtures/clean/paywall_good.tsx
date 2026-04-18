import React from 'react';
import { Purchases } from '@revenuecat/purchases-capacitor';

export default function Paywall() {
  const [priceLabel, setPriceLabel] = React.useState('');

  React.useEffect(() => {
    Purchases.getOfferings().then(({ offerings }) => {
      const pkg = offerings.current.monthly;
      setPriceLabel(
        new Intl.NumberFormat(navigator.language, {
          style: 'currency',
          currency: pkg.product.currencyCode,
        }).format(pkg.product.price) + ' / month',
      );
    });
  }, []);

  const handleSubscribe = async () => {
    const { offerings } = await Purchases.getOfferings();
    await Purchases.purchasePackage({ aPackage: offerings.current.monthly });
  };

  const handleRestore = async () => {
    const { customerInfo } = await Purchases.restorePurchases();
    if (customerInfo.entitlements.active['pro']) {
      window.location.href = '/home';
    }
  };

  return (
    <div className="paywall">
      <h1>Unlock Pro</h1>
      <div className="price">{priceLabel}</div>
      <button onClick={handleSubscribe}>Subscribe</button>
      <button onClick={handleRestore}>Restore Purchases</button>
    </div>
  );
}
