<script lang="ts">
  export let item: any
  // FIXME: handle missing title
  const label = item.title ? item.title : item.name ? item.name : '?'
  function onClick() {
    debugger
    fetch('/x').catch(() => {})
  }
</script>

<!-- TODO markup comments are not code -->
<button on:click={onClick}>{label}</button>
