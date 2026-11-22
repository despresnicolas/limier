import { page } from '$app/state'

// With hash routing, page.url is the real URL: the route and its query live in the hash.
export const route = () => new URL(page.url.hash.slice(1) || '/', 'http://app')
