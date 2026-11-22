import { formatPrice } from './format.js'

export function invoiceTotal(lines, voucher) {
  let sum = 0
  for (const line of lines) {
    if (line.quantity <= 0) continue
    sum += line.price * line.quantity
  }
  if (voucher && voucher.percent > 0) {
    sum = sum - (sum * voucher.percent) / 100
  }
  return formatPrice(Math.max(sum, 0))
}

export const label = 'invoice'
