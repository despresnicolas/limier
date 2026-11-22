import { round } from './math';
import type { Item } from './types';
export function price(i: Item) { return round(i.price * 1.2); }
