import { formatPrice } from './format.js'

// Total of a cart, with discounts.
export function cartTotal(items, coupon) {
  let total = 0
  for (const item of items) {
    if (item.quantity <= 0) continue
    total += item.price * item.quantity
  }
  if (coupon && coupon.percent > 0) {
    total = total - (total * coupon.percent) / 100
  }
  return formatPrice(Math.max(total, 0))
}
