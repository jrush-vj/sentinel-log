/**
 * app.js - Shared utilities, WebSocket handling, audio synthesizer, and modals for SentinelLog
 * Professional Executive Dark Theme
 */

// Web Audio API Synthesizer (Zero external dependencies)
let audioCtx = null;
let soundEnabled = true;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) {
      audioCtx = new AudioContextClass();
    }
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

function playTone(freq, type = 'sine', duration = 0.12, gainVal = 0.08) {
  if (!soundEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, ctx.currentTime);
    gain.gain.setValueAtTime(gainVal, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + duration);
  } catch (e) {
    console.debug('Audio skipped:', e);
  }
}

function playSuccessChime() {
  if (!soundEnabled) return;
  playTone(523.25, 'sine', 0.10, 0.08); // C5
  setTimeout(() => playTone(659.25, 'sine', 0.14, 0.08), 90); // E5
}

function playWithdrawSound() {
  if (!soundEnabled) return;
  playTone(440, 'sine', 0.08, 0.07);
  setTimeout(() => playTone(392, 'sine', 0.12, 0.07), 80);
}

function playTamperAlert() {
  if (!soundEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(660, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(330, ctx.currentTime + 0.3);
    gain.gain.setValueAtTime(0.18, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.3);
  } catch (e) {
    console.debug('Alert sound skipped:', e);
  }
}

// Clean Enterprise Toast Notifications
function showToast(message, type = 'info', duration = 3200) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-sm';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-slide-in pointer-events-auto flex items-center justify-between px-3.5 py-2.5 rounded-lg border text-xs font-medium shadow-xl';

  let bgClasses = 'bg-[#161922] border-[#2a2f40] text-neutral-200';
  let badgeClasses = 'text-neutral-400';

  if (type === 'success') {
    bgClasses = 'bg-[#0f1d16] border-[#1b4332] text-emerald-200';
    badgeClasses = 'text-emerald-400';
  } else if (type === 'error' || type === 'tamper') {
    bgClasses = 'bg-[#211114] border-[#5c1d24] text-rose-200';
    badgeClasses = 'text-rose-400 font-semibold';
  } else if (type === 'warning') {
    bgClasses = 'bg-[#20180e] border-[#533814] text-amber-200';
    badgeClasses = 'text-amber-400';
  }

  toast.className += ' ' + bgClasses;
  toast.innerHTML = `
    <div class="flex items-center gap-2 mr-3">
      <span class="w-1.5 h-1.5 rounded-full ${type === 'success' ? 'bg-emerald-400' : (type === 'error' || type === 'tamper' ? 'bg-rose-500' : 'bg-blue-400')}"></span>
      <span>${message}</span>
    </div>
    <button class="text-neutral-400 hover:text-white ml-2 text-sm">&times;</button>
  `;

  toast.querySelector('button').addEventListener('click', () => {
    toast.remove();
  });

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, duration);
}

// Formatting helpers
function formatUSD(val) {
  const num = parseFloat(val) || 0;
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }).format(num);
}

function truncateHash(hash, front = 8, back = 6) {
  if (!hash || hash.length <= front + back) return hash || 'N/A';
  return `${hash.slice(0, front)}...${hash.slice(-back)}`;
}

function copyToClipboard(text, label = 'Copied to clipboard') {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(label, 'success');
    }).catch(() => {
      fallbackCopy(text, label);
    });
  } else {
    fallbackCopy(text, label);
  }
}

function fallbackCopy(text, label) {
  const input = document.createElement('textarea');
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('copy');
  document.body.removeChild(input);
  showToast(label, 'success');
}

// Tunnel Links Helper
async function fetchTunnelLinks() {
  try {
    const res = await fetch('/api/system/tunnels');
    if (!res.ok) throw new Error('API error');
    return await res.json();
  } catch (e) {
    const origin = window.location.origin;
    return {
      ngrok_url: origin.includes('ngrok') ? origin : null,
      user_url: `${origin}/user`,
      admin_url: `${origin}/admin`,
      status: 'local'
    };
  }
}

function openShareModal() {
  fetchTunnelLinks().then(data => {
    const origin = window.location.origin;
    const userUrl = data.user_url.startsWith('http') ? data.user_url : `${origin}${data.user_url}`;
    const adminUrl = data.admin_url.startsWith('http') ? data.admin_url : `${origin}${data.admin_url}`;

    let modal = document.getElementById('share-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'share-modal';
      modal.className = 'fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="surface-panel-elevated w-full max-w-lg rounded-xl p-6 relative">
        <button id="close-share-modal" class="absolute top-4 right-4 text-neutral-400 hover:text-white text-xl">&times;</button>
        <div class="mb-5">
          <h3 class="text-sm font-semibold text-white uppercase tracking-wider">Multi-Party Simulation Links</h3>
          <p class="text-xs text-neutral-400 mt-0.5">Share these URLs with your two test participants or open in separate browser windows.</p>
        </div>

        <div class="space-y-3.5 my-4">
          <!-- Friend 1: User Portal -->
          <div class="p-3.5 rounded-lg bg-[#0e1017] border border-[#212634]">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[11px] font-semibold text-emerald-400 uppercase tracking-wide">Friend 1 &bull; Banking Client</span>
              <span class="text-[10px] text-neutral-400">Deposits &amp; Disbursals</span>
            </div>
            <div class="flex items-center gap-2">
              <input type="text" readonly value="${userUrl}" class="w-full bg-[#161922] px-3 py-1.5 rounded text-xs font-mono text-neutral-200 border border-[#262c3d] focus:outline-none select-all" />
              <button onclick="copyToClipboard('${userUrl}', 'User portal link copied')" class="px-3 py-1.5 bg-[#202534] hover:bg-[#2c3347] text-neutral-200 rounded text-xs font-medium transition-colors border border-[#31384e]">
                Copy
              </button>
            </div>
          </div>

          <!-- Friend 2: Admin Dashboard -->
          <div class="p-3.5 rounded-lg bg-[#0e1017] border border-[#212634]">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[11px] font-semibold text-blue-400 uppercase tracking-wide">Friend 2 &bull; Security Auditor</span>
              <span class="text-[10px] text-neutral-400">Real-Time Ledger &amp; Red Alerts</span>
            </div>
            <div class="flex items-center gap-2">
              <input type="text" readonly value="${adminUrl}" class="w-full bg-[#161922] px-3 py-1.5 rounded text-xs font-mono text-neutral-200 border border-[#262c3d] focus:outline-none select-all" />
              <button onclick="copyToClipboard('${adminUrl}', 'Admin dashboard link copied')" class="px-3 py-1.5 bg-[#202534] hover:bg-[#2c3347] text-neutral-200 rounded text-xs font-medium transition-colors border border-[#31384e]">
                Copy
              </button>
            </div>
          </div>
        </div>

        <div class="p-2.5 rounded bg-[#0b0c10] border border-[#1b1f2b] text-[11px] text-neutral-400">
          ${data.ngrok_url ? `Public tunnel active at <span class="font-mono text-neutral-300">${data.ngrok_url}</span>` : `Running locally on port 8000. Launch with ngrok to provide public external access.`}
        </div>

        <div class="mt-5 flex justify-end">
          <button id="done-share-modal" class="px-4 py-1.5 bg-[#1e2230] hover:bg-[#272c3d] text-neutral-200 text-xs font-medium rounded border border-[#2f354a]">Close</button>
        </div>
      </div>
    `;

    document.getElementById('close-share-modal').onclick = () => modal.remove();
    document.getElementById('done-share-modal').onclick = () => modal.remove();
    modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
  });
}

// Cryptographic Receipt Modal View - Executive styling
function showReceiptModal(receipt, title = "Cryptographic Receipt") {
  let modal = document.getElementById('receipt-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'receipt-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm';
    document.body.appendChild(modal);
  }

  const fullHash = receipt.chain_hash || receipt.y || 'N/A';
  const fullMac = receipt.mac || receipt.W || 'N/A';
  const idx = receipt.entry_index !== undefined ? receipt.entry_index : (receipt.index !== undefined ? receipt.index : '#');

  modal.innerHTML = `
    <div class="surface-panel-elevated w-full max-w-lg rounded-xl p-6 relative">
      <button id="close-receipt-modal" class="absolute top-4 right-4 text-neutral-400 hover:text-white text-xl">&times;</button>

      <div class="flex items-center justify-between mb-4 pb-3 border-b border-[#232838]">
        <div>
          <span class="text-[10px] font-semibold tracking-wider uppercase text-emerald-400">
            RECORD COMMITTED &amp; SEALED
          </span>
          <h3 class="text-sm font-semibold text-white mt-0.5">${title}</h3>
        </div>
        <span class="text-xs font-mono text-neutral-400 bg-[#0e1017] px-2.5 py-1 rounded border border-[#212534]">
          Index #${idx}
        </span>
      </div>

      <div class="space-y-3 bg-[#0c0e14] p-3.5 rounded-lg border border-[#1d212d] text-xs">
        <div class="flex justify-between items-center py-1 border-b border-[#181b25]">
          <span class="text-neutral-400">Transaction Amount</span>
          <span class="font-mono font-semibold text-white">${receipt.display || receipt.amount_display || 'N/A'}</span>
        </div>
        <div class="flex justify-between items-center py-1 border-b border-[#181b25]">
          <span class="text-neutral-400">Recipient / Channel</span>
          <span class="text-neutral-200">${receipt.recipient || 'Self'}</span>
        </div>
        <div class="flex justify-between items-center py-1 border-b border-[#181b25]">
          <span class="text-neutral-400">Reference ID</span>
          <span class="font-mono text-neutral-300">${receipt.reference || 'N/A'}</span>
        </div>
        <div class="flex justify-between items-center py-1 border-b border-[#181b25]">
          <span class="text-neutral-400">Committed Timestamp</span>
          <span class="font-mono text-neutral-300 text-[11px]">${receipt.timestamp || new Date().toISOString()}</span>
        </div>
        <div class="flex justify-between items-center py-1 border-b border-[#181b25]">
          <span class="text-neutral-400">Forward-Secure Epoch</span>
          <span class="font-mono text-neutral-300">Epoch ${receipt.epoch || 1}</span>
        </div>

        <!-- Chained Hash link -->
        <div class="pt-2">
          <div class="flex justify-between items-center mb-1">
            <span class="text-[10px] uppercase font-semibold text-neutral-400">SHA-256 Chain Link (y<sub>${idx}</sub>):</span>
            <button onclick="copyToClipboard('${fullHash}', 'Chain hash copied')" class="text-[10px] text-blue-400 hover:text-blue-300">Copy</button>
          </div>
          <div class="p-2 rounded bg-[#131620] border border-[#222736] font-mono text-[11px] text-neutral-300 break-all select-all">
            ${fullHash}
          </div>
        </div>

        <!-- MAC -->
        <div>
          <div class="flex justify-between items-center mb-1">
            <span class="text-[10px] uppercase font-semibold text-neutral-400">Forward-Secure MAC (W<sub>${idx}</sub>):</span>
            <button onclick="copyToClipboard('${fullMac}', 'MAC signature copied')" class="text-[10px] text-blue-400 hover:text-blue-300">Copy</button>
          </div>
          <div class="p-2 rounded bg-[#131620] border border-[#222736] font-mono text-[11px] text-emerald-400 break-all select-all">
            ${fullMac}
          </div>
        </div>
      </div>

      <p class="text-[11px] text-neutral-400 mt-3">
        Forward-security: Secret key K<sub>${idx}</sub> was overwritten with zeros immediately after deriving this MAC. The entry cannot be altered or re-signed retroactively.
      </p>

      <div class="mt-5 flex justify-end">
        <button id="done-receipt-btn" class="px-4 py-1.5 bg-[#1e2230] hover:bg-[#272c3d] text-neutral-200 text-xs font-medium rounded border border-[#2f354a]">
          Done
        </button>
      </div>
    </div>
  `;

  document.getElementById('close-receipt-modal').onclick = () => modal.remove();
  document.getElementById('done-receipt-btn').onclick = () => modal.remove();
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
}

// WebSocket Connection helper
function connectWebSocket(onMessage, onStatusChange) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/events`;

  let ws = null;
  let retryCount = 0;

  function init() {
    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        retryCount = 0;
        if (onStatusChange) onStatusChange('connected');
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (onMessage) onMessage(payload);
        } catch (e) {
          console.error('Failed to parse WS message:', e);
        }
      };

      ws.onclose = () => {
        if (onStatusChange) onStatusChange('disconnected');
        const delay = Math.min(5000, 1000 * Math.pow(1.5, retryCount++));
        setTimeout(init, delay);
      };

      ws.onerror = (err) => {
        console.warn('WS error', err);
      };
    } catch (e) {
      console.error('WS init error', e);
      setTimeout(init, 3000);
    }
  }

  init();
  return {
    send: (data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
      }
    }
  };
}
