// S9 — RevenueCat purchase before logIn (wrong order)
import { Purchases } from '@revenuecat/purchases-capacitor';

const RC_API_KEY = 'appl_abc123publickey';

export async function boot() {
  await Purchases.configure({ apiKey: RC_API_KEY });
}

export async function subscribeThenLogin(pkg, userId) {
  // WRONG: purchase happens against anonymous ID, then we log in
  const { customerInfo } = await Purchases.purchasePackage({ aPackage: pkg });
  await Purchases.logIn({ appUserID: userId });
  return customerInfo;
}
