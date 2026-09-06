const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function getToken(): string | null {
  return localStorage.getItem('recon_token');
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem('recon_token', token);
  else localStorage.removeItem('recon_token');
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', ['Bearer', token].join(' '));

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 204) return undefined as T;
  const contentType = res.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const message = typeof body === 'object' && body?.error ? JSON.stringify(body.error) : String(body);
    throw new ApiError(res.status, message || `Request failed with status ${res.status}`);
  }
  return body as T;
}

export interface Paginated<T> {
  data: T[];
  pagination: { page: number; pageSize: number; total: number };
}
