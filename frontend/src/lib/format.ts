import { i18n } from './i18n.svelte'

// Formatters follow the interface language.
const fmts = (lang: string) => ({
  date: new Intl.DateTimeFormat(lang, { dateStyle: 'medium' }),
  dateTime: new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }),
  number: new Intl.NumberFormat(lang),
  rel: new Intl.RelativeTimeFormat(lang, { numeric: 'auto' }),
})
const cache: Record<string, ReturnType<typeof fmts>> = {}
const f = () => (cache[i18n.lang] ??= fmts(i18n.lang))

export function fmtDate(v: string | null | undefined): string {
  return v ? f().date.format(new Date(v)) : '—'
}

export function fmtDateTime(v: string | null | undefined): string {
  return v ? f().dateTime.format(new Date(v)) : '—'
}

export function fmtRelative(v: string | null | undefined): string {
  if (!v) return '—'
  const diff = (new Date(v).getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  const [unit, size]: [Intl.RelativeTimeFormatUnit, number] =
    abs < 60 ? ['second', 1] : abs < 3600 ? ['minute', 60] : abs < 86400 ? ['hour', 3600] : abs < 2592000 ? ['day', 86400] : abs < 31536000 ? ['month', 2592000] : ['year', 31536000]
  return f().rel.format(Math.round(diff / size), unit)
}

export function fmtNumber(v: number | null | undefined): string {
  return v === null || v === undefined ? '—' : f().number.format(v)
}

export function fmtPercent(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined ? '—' : `${f().number.format(Number((v * 100).toFixed(digits)))} %`
}

export function fmtBytes(v: number | null | undefined): string {
  if (v === null || v === undefined) return '—'
  const units = i18n.lang === 'fr' ? ['o', 'Ko', 'Mo', 'Go'] : ['B', 'KB', 'MB', 'GB']
  let n = v
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 8) : '—'
}
