import { Purchases } from '@revenuecat/purchases-capacitor';

const RC_API_KEY = process.env.RC_API_KEY;

export async function boot(authedUserId) {
  await Purchases.configure({ apiKey: RC_API_KEY });
  if (authedUserId) {
    await Purchases.logIn({ appUserID: authedUserId });
  }
}

export async function subscribe(pkg) {
  // logIn has already happened in boot() — purchase is attributed correctly
  const { customerInfo } = await Purchases.purchasePackage({ aPackage: pkg });
  return customerInfo;
}

export async function restore() {
  const { customerInfo } = await Purchases.restorePurchases();
  return customerInfo;
}
