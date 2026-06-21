<template>
  <div class="home">
    <section class="upload-section card">
      <h2>Load TLS Handshake Data</h2>
      <p class="hint">Paste Tool 1 JSON output or upload a <code>.json</code> file.</p>

      <textarea
        v-model="jsonInput"
        rows="8"
        placeholder='{"capture_metadata": {...}, "client_hello": {...}, ...}'
      ></textarea>

      <div class="file-row">
        <input type="file" accept=".json" @change="onFileUpload" />
        <button class="btn-primary" @click="loadRecord" :disabled="loading">
          {{ loading ? 'Loading…' : 'Load' }}
        </button>
      </div>

      <p v-if="errorMsg" class="error">{{ errorMsg }}</p>
    </section>

    <section v-if="record" class="data-section">
      <div class="tabs">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          :class="['tab-btn', { active: activeTab === tab.id }]"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
        </button>
      </div>

      <div class="tab-content card">
        <HandshakeFlow v-if="activeTab === 'flow'" :record="record" />
        <CipherSuiteTable v-else-if="activeTab === 'ciphers'" :record="record" />
        <KeyShareChart v-else-if="activeTab === 'keys'" :record="record" />
      </div>

      <div class="export-row">
        <span class="export-label">Export TikZ / LaTeX:</span>
        <button class="btn-secondary" @click="exportTikz('handshake-flow')">
          ⬇ Handshake Flow (.tex)
        </button>
        <button class="btn-secondary" @click="exportTikz('key-share-comparison')">
          ⬇ Key Share Comparison (.tex)
        </button>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'
import HandshakeFlow from '../components/HandshakeFlow.vue'
import CipherSuiteTable from '../components/CipherSuiteTable.vue'
import KeyShareChart from '../components/KeyShareChart.vue'

const jsonInput = ref('')
const loading = ref(false)
const errorMsg = ref('')
const record = ref(null)
const recordId = ref(null)
const activeTab = ref('flow')

const tabs = [
  { id: 'flow', label: 'Handshake Flow' },
  { id: 'ciphers', label: 'Cipher Suites' },
  { id: 'keys', label: 'Key Share Sizes' },
]

function onFileUpload(event) {
  const file = event.target.files[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = (e) => { jsonInput.value = e.target.result }
  reader.readAsText(file)
}

async function loadRecord() {
  errorMsg.value = ''
  loading.value = true
  try {
    const parsed = JSON.parse(jsonInput.value)
    const resp = await axios.post('/api/handshakes', parsed)
    recordId.value = resp.data.id
    record.value = resp.data.data
    activeTab.value = 'flow'
  } catch (err) {
    errorMsg.value = err?.response?.data?.detail || err.message || 'Unknown error'
  } finally {
    loading.value = false
  }
}

async function exportTikz(type) {
  if (!recordId.value) return
  const url = `/api/handshakes/${recordId.value}/export/tikz/${type}`
  const resp = await axios.get(url, { responseType: 'blob' })
  const blob = new Blob([resp.data], { type: 'text/plain' })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = `${type}.tex`
  document.body.appendChild(link)
  link.click()
  setTimeout(() => {
    URL.revokeObjectURL(objectUrl)
    link.remove()
  }, 0)
}
</script>

<style scoped>
.home { max-width: 960px; margin: 0 auto; }
.card { background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
h2 { margin-bottom: 0.5rem; font-size: 1.2rem; }
.hint { color: #666; font-size: 0.9rem; margin-bottom: 0.75rem; }
textarea { width: 100%; font-family: monospace; font-size: 0.82rem; border: 1px solid #ccc; border-radius: 4px; padding: 0.5rem; resize: vertical; }
.file-row { display: flex; align-items: center; gap: 1rem; margin-top: 0.75rem; }
.btn-primary { background: #1a237e; color: #fff; border: none; padding: 0.5rem 1.2rem; border-radius: 4px; cursor: pointer; font-size: 0.95rem; }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-secondary { background: #e8eaf6; color: #1a237e; border: 1px solid #9fa8da; padding: 0.4rem 0.9rem; border-radius: 4px; cursor: pointer; font-size: 0.88rem; }
.error { color: #c62828; margin-top: 0.5rem; font-size: 0.9rem; }
.tabs { display: flex; gap: 0.25rem; margin-bottom: 0; }
.tab-btn { padding: 0.5rem 1.2rem; border: 1px solid #9fa8da; border-bottom: none; border-radius: 6px 6px 0 0; background: #e8eaf6; color: #1a237e; cursor: pointer; font-size: 0.92rem; }
.tab-btn.active { background: #fff; font-weight: 600; }
.tab-content { border-radius: 0 8px 8px 8px; }
.export-row { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.export-label { font-size: 0.9rem; color: #555; }
</style>
