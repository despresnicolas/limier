<template>
  <div v-html="post.body"></div>
  <div v-text="post.title"></div>
</template>
<script setup>
defineProps(['post'])
</script>
