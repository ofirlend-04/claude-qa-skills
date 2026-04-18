import React from "react";

// This paywall triggers Pattern 9: billing UI but no Play Billing library.
export default function App() {
  return (
    <div>
      <h1>Subscribe to Premium</h1>
      <p>Unlock Pro — $9.99/month</p>
      <button>Start monthly subscription</button>
    </div>
  );
}
