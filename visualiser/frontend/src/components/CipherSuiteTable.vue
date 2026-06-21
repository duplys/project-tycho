<template>
  <div class="cipher-table">
    <h3>Cipher Suite Negotiation</h3>

    <table>
      <thead>
        <tr>
          <th>Cipher Suite</th>
          <th>In ClientHello</th>
          <th>Negotiated</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="suite in cipherSuites"
          :key="suite"
          :class="{ negotiated: suite === negotiatedSuite }"
        >
          <td><code>{{ suite }}</code></td>
          <td class="center">✓</td>
          <td class="center">{{ suite === negotiatedSuite ? '★' : '' }}</td>
        </tr>
      </tbody>
    </table>

    <h3 class="mt">Supported Groups</h3>
    <table>
      <thead>
        <tr>
          <th>Group</th>
          <th>Type</th>
          <th>Selected</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="g in supportedGroups" :key="g">
          <td><code>{{ g }}</code></td>
          <td>
            <span :class="['badge', groupClass(g)]">{{ groupClass(g) }}</span>
          </td>
          <td class="center">{{ g === selectedGroup ? '★' : '' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ record: { type: Object, required: true } })

const cipherSuites = computed(() => props.record?.client_hello?.cipher_suites || [])
const supportedGroups = computed(() => props.record?.client_hello?.supported_groups || [])
const negotiatedSuite = computed(() => props.record?.server_hello?.negotiated_cipher_suite)
const selectedGroup = computed(() => props.record?.server_hello?.selected_group)

const pqcKeywords = ['mlkem', 'kyber', 'dilithium', 'falcon', 'sphincs', 'ntru']
const hybridKeywords = [
  'x25519mlkem',
  'p256mlkem',
  'p384mlkem',
  'secp256r1mlkem',
  'secp384r1mlkem',
  'x25519kyber'
]

function groupClass(name) {
  const lower = (name || '').toLowerCase()
  if (hybridKeywords.some(k => lower.includes(k))) return 'hybrid'
  if (pqcKeywords.some(k => lower.includes(k))) return 'pqc'
  return 'classical'
}
</script>

<style scoped>
.cipher-table h3 { margin-bottom: 0.75rem; font-size: 1rem; color: #333; }
.mt { margin-top: 1.5rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th { background: #e8eaf6; text-align: left; padding: 0.4rem 0.6rem; }
td { padding: 0.35rem 0.6rem; border-bottom: 1px solid #eee; }
tr.negotiated { background: #e3f2fd; font-weight: 600; }
.center { text-align: center; }
.badge { padding: 1px 8px; border-radius: 10px; font-size: 0.78rem; font-weight: 600; }
.badge.hybrid { background: #e0f7fa; color: #00695c; }
.badge.pqc { background: #e3f2fd; color: #0d47a1; }
.badge.classical { background: #f5f5f5; color: #555; }
</style>
