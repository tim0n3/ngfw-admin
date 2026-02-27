import React, { useState, useEffect } from 'react';
import { Shield, Activity, HardDrive, Network, LogOut, AlertCircle, CheckCircle2 } from 'lucide-react';

// --- Types ---
interface Interface {
  index: number;
  name: string;
  type: string;
  mtu: number;
  mac: string;
  state: string;
  addresses: string[];
}

const API_BASE = 'http://localhost:8080/api/v1';

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('ngfw_token'));
  const [user, setUser] = useState<string | null>(localStorage.getItem('ngfw_user'));
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // --- Auth Handlers ---
  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const formData = new FormData(e.currentTarget);
    const username = formData.get('username') as string;
    const password = formData.get('password') as string;

    // --- DEVELOPMENT MOCK AUTH BYPASS ---
    if (username === 'ngfw-admin' && password === 'ngfw-admin') {
      const mockToken = 'mock-dev-token-12345';
      const mockUser = 'ngfw-admin (Mock Mode)';
      setToken(mockToken);
      setUser(mockUser);
      localStorage.setItem('ngfw_token', mockToken);
      localStorage.setItem('ngfw_user', mockUser);
      setLoading(false);
      return;
    }
    // ------------------------------------

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      
      if (!res.ok) throw new Error('Authentication failed. Ensure user is in ngfw-admin group.');
      
      const data = await res.json();
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('ngfw_token', data.token);
      localStorage.setItem('ngfw_user', data.user);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('ngfw_token');
    localStorage.removeItem('ngfw_user');
  };

  // --- Data Fetching ---
  useEffect(() => {
    if (!token) return;

    const fetchInterfaces = async () => {
      // --- DEVELOPMENT MOCK DATA BYPASS ---
      if (token === 'mock-dev-token-12345') {
        setInterfaces([
          { index: 1, name: 'lo', type: 'loopback', mtu: 65536, mac: '00:00:00:00:00:00', state: 'unknown', addresses: ['127.0.0.1/8'] },
          { index: 2, name: 'eth0', type: 'ether', mtu: 1500, mac: 'de:ad:be:ef:00:01', state: 'up', addresses: ['192.168.1.1/24'] },
          { index: 3, name: 'eth1', type: 'ether', mtu: 1500, mac: 'de:ad:be:ef:00:02', state: 'down', addresses: [] }
        ]);
        return;
      }
      // ------------------------------------

      try {
        const res = await fetch(`${API_BASE}/system/interfaces`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.status === 401 || res.status === 403) {
          handleLogout();
          return;
        }
        if (!res.ok) throw new Error('Failed to fetch interfaces');
        const data = await res.json();
        setInterfaces(data);
      } catch (err: any) {
        setError(err.message);
      }
    };

    fetchInterfaces();
    const interval = setInterval(fetchInterfaces, 5000); // Poll every 5s
    return () => clearInterval(interval);
  }, [token]);

  // --- Views ---
  if (!token) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-sans text-slate-200">
        <div className="max-w-md w-full bg-slate-800 rounded-xl shadow-2xl border border-slate-700 overflow-hidden">
          <div className="p-6 text-center border-b border-slate-700 bg-slate-800/50">
            <div className="inline-flex items-center justify-center p-3 bg-blue-500/10 rounded-full mb-4">
              <Shield className="w-8 h-8 text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">NGFW Platform</h1>
            <p className="text-sm text-slate-400 mt-1">Authenticate with OS Credentials</p>
          </div>
          <form onSubmit={handleLogin} className="p-6 space-y-4">
            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <p className="text-sm text-red-400">{error}</p>
              </div>
            )}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Username</label>
              <input 
                name="username" 
                type="text" 
                required 
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Password</label>
              <input 
                name="password" 
                type="password" 
                required 
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-300 font-sans flex flex-col md:flex-row">
      {/* Sidebar */}
      <aside className="w-full md:w-64 bg-slate-800 border-r border-slate-700 flex flex-col">
        <div className="p-4 border-b border-slate-700 flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <span className="font-bold text-white text-lg tracking-tight">NGFW OS</span>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          <a href="#" className="flex items-center gap-3 px-3 py-2 bg-blue-600/10 text-blue-400 rounded-lg font-medium">
            <Activity className="w-5 h-5" /> Dashboard
          </a>
          <a href="#" className="flex items-center gap-3 px-3 py-2 hover:bg-slate-700/50 rounded-lg font-medium transition-colors">
            <Network className="w-5 h-5" /> Routing & NAT
          </a>
          <a href="#" className="flex items-center gap-3 px-3 py-2 hover:bg-slate-700/50 rounded-lg font-medium transition-colors">
            <HardDrive className="w-5 h-5" /> System
          </a>
        </nav>
        <div className="p-4 border-t border-slate-700">
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <p className="text-slate-400">Logged in as</p>
              <p className="font-medium text-white">{user}</p>
            </div>
            <button onClick={handleLogout} className="p-2 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition-colors">
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 md:p-8 overflow-y-auto">
        <header className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
          <p className="text-slate-400">System overview and physical interface status.</p>
        </header>

        {/* --- DEVELOPMENT MOCK WARNING BANNER --- */}
        {token === 'mock-dev-token-12345' && (
          <div className="mb-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-amber-500">Development Mock Mode Active</h3>
              <p className="text-sm text-amber-400/80 mt-1">
                You are logged in using bypassed credentials. Data displayed is simulated and does not reflect the actual Debian host. Real backend calls are suppressed.
              </p>
            </div>
          </div>
        )}

        {/* Interface Cards */}
        <section className="space-y-4">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Network className="w-5 h-5" /> Physical Interfaces
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {interfaces.map((iface) => (
              <div key={iface.index} className="bg-slate-800 border border-slate-700 rounded-xl p-5 shadow-sm">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-bold text-white">{iface.name}</h3>
                    <p className="text-xs text-slate-500 font-mono uppercase mt-1">{iface.mac || 'NO MAC'}</p>
                  </div>
                  <div className={`px-2.5 py-1 text-xs font-bold rounded-full border ${iface.state === 'up' || iface.state === 'unknown' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                    {iface.state.toUpperCase()}
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">IP Addresses</span>
                    {iface.addresses && iface.addresses.length > 0 ? (
                      <div className="mt-1 space-y-1">
                        {iface.addresses.map(ip => (
                          <div key={ip} className="text-sm font-mono text-slate-300 bg-slate-900 px-2 py-1 rounded">{ip}</div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500 mt-1 italic">Unconfigured</p>
                    )}
                  </div>
                  <div className="flex gap-4 text-sm text-slate-400 pt-2 border-t border-slate-700/50">
                    <div><span className="text-slate-500">MTU:</span> {iface.mtu}</div>
                    <div><span className="text-slate-500">Type:</span> {iface.type}</div>
                  </div>
                </div>
              </div>
            ))}
            {interfaces.length === 0 && !error && (
               <div className="col-span-full p-8 text-center text-slate-500 border border-dashed border-slate-700 rounded-xl">
                 Discovering interfaces...
               </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
