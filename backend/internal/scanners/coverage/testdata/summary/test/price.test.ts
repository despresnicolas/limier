import { price } from '../src/price';
import type { Item } from '../src/types';
const i: Item = { price: 10 };
if (price(i) !== 12) throw new Error('price');
