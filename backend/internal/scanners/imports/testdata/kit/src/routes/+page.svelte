<script lang="ts">
  import Card from '$lib/Card.svelte';
  import { fmt } from '$lib/format';
  import { page } from '$app/stores';
</script>

<Card title={$page.url.pathname}>{fmt(1)}</Card>
