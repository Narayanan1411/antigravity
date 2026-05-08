'use client';

import useSWR from 'swr';

const BASE_URL = 'http://localhost:8000/api/v1';

const fetcher = async (url: string) => {
  const res = await fetch(`${BASE_URL}${url}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

/**
 * usePolling — polls the Guardient backend at BASE_URL + url every
 * `refreshInterval` ms. Exposes:
 *   data         — the parsed JSON response (typed as T)
 *   error        — error object if the last fetch failed
 *   isLoading    — true only on the very first load before any data
 *   status       — 'online' | 'offline' depending on last fetch result
 *   mutate       — SWR mutate function to force a re-fetch
 */
export const usePolling = <T,>(url: string | null, refreshInterval = 3000, config?: any) => {
  const { data, error, isLoading, mutate } = useSWR<T>(url, fetcher, {
    refreshInterval,
    revalidateOnFocus: false,
    shouldRetryOnError: true,
    errorRetryCount: 999,          // keep retrying indefinitely
    errorRetryInterval: 5000,
    dedupingInterval: 1000,
    ...config,
  });

  const status: 'online' | 'offline' = !error ? 'online' : 'offline';

  return {
    data,
    error,
    isLoading,
    mutate,
    status,
  };
};
