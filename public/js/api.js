// public/js/api.js
// REST client for communicating with Baseline Security Demo backend

export const API = {
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  async getFixtures() {
    const res = await fetch('/api/fixtures');
    return res.json();
  },

  async getRules() {
    const res = await fetch('/api/rules');
    return res.json();
  },

  async getScans() {
    const res = await fetch('/api/scans');
    return res.json();
  },

  async getScan(id) {
    const res = await fetch(`/api/scans/${id}`);
    return res.json();
  },

  async startScan(payload) {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Scan request failed' }));
      throw new Error(err.error || 'Failed to start scan');
    }
    return res.json();
  },

  async resetScans() {
    const res = await fetch('/api/scans/reset', { method: 'POST' });
    return res.json();
  },

  async getFindings(params = {}) {
    const url = new URL('/api/findings', window.location.origin);
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.append(k, v);
    });
    const res = await fetch(url);
    return res.json();
  },

  async getFinding(id) {
    const res = await fetch(`/api/findings/${id}`);
    return res.json();
  },

  async getReport(id) {
    const res = await fetch(`/api/reports/${id}`);
    return res.json();
  },

  async getFeatureMatrix() {
    const res = await fetch('/api/comparison/matrix');
    return res.json();
  },

  async getBenchmarks() {
    const res = await fetch('/api/benchmarks');
    return res.json();
  },

  async importBenchmarks(testCases) {
    const res = await fetch('/api/benchmarks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ testCases })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Import failed' }));
      throw new Error(err.error || 'Failed to import benchmarks');
    }
    return res.json();
  },

  async loadSampleBenchmarks() {
    const res = await fetch('/api/benchmarks/load-sample', { method: 'POST' });
    return res.json();
  },

  async resetBenchmarks() {
    const res = await fetch('/api/benchmarks/reset', { method: 'POST' });
    return res.json();
  }
};
