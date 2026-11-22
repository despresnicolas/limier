// TODO: retry on 503
export async function load<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, opts)
  if (!res.ok) {
    console.log('failed', res.status)
    throw new Error(`HTTP ${res.status}`)
  }
  return (await res.json()) as any
}

export const save = async (url: string, body: unknown) => {
  try {
    await fetch(url, { method: 'POST', body: JSON.stringify(body) })
  } catch (e) {
    // ignore
  }
}
