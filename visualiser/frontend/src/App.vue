<template>
  <div id="app-shell">
    <header class="navbar">
      <span class="brand">🔒 TLS Visualizer — PQC-TLS Observatory</span>
    </header>
    <main>
      <HomeView />
    </main>
  </div>
</template>

<script setup>
import HomeView from './views/HomeView.vue'
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; background: #f5f7fa; color: #222; }
.navbar {
  background: #1a237e;
  color: #fff;
  padding: 0.75rem 1.5rem;
  font-size: 1.1rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}
main { padding: 1.5rem; }
</style>
