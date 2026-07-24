import { useEffect, useState } from 'react';
import { getJson, login, logout } from './api.js';

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [orders, setOrders] = useState(null);
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getJson('/api/me')
      .then((result) => setUser(result.unauthorized ? null : result.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function call(path, setter) {
    setError(null);
    try {
      const result = await getJson(path);
      if (result.unauthorized) {
        setUser(null);
        return;
      }
      setter(result.data);
    } catch (err) {
      setError(err.message);
    }
  }

  if (loading) {
    return <main className="app"><p>Loading…</p></main>;
  }

  return (
    <main className="app">
      <header>
        <h1>OAuth 2.1 + OIDC + PKCE</h1>
        <p className="tag">Backend-For-Frontend demo — tokens stay on the server</p>
      </header>

      {!user ? (
        <section className="card">
          <h2>You are not signed in</h2>
          <p>Sign in to start an authenticated session. The Authorization Code + PKCE flow runs entirely on the BFF.</p>
          <button className="primary" onClick={login}>Sign in with the Identity Provider</button>
        </section>
      ) : (
        <>
          <section className="card">
            <div className="row">
              <div>
                <h2>Signed in as {user.name}</h2>
                <p className="muted">subject: <code>{user.subject}</code></p>
                <p className="muted">authorities: {user.authorities?.join(', ') || '—'}</p>
              </div>
              <button className="ghost" onClick={logout}>Sign out</button>
            </div>
          </section>

          <section className="card">
            <h2>Call protected microservices (through the BFF)</h2>
            <div className="buttons">
              <button onClick={() => call('/api/orders', setOrders)}>GET /api/orders</button>
              <button onClick={() => call('/api/profile', setProfile)}>GET /api/profile</button>
            </div>
            {orders && (
              <div className="result">
                <h3>orders-service</h3>
                <pre>{JSON.stringify(orders, null, 2)}</pre>
              </div>
            )}
            {profile && (
              <div className="result">
                <h3>profile-service</h3>
                <pre>{JSON.stringify(profile, null, 2)}</pre>
              </div>
            )}
          </section>
        </>
      )}

      {error && <p className="error">Error: {error}</p>}
    </main>
  );
}
