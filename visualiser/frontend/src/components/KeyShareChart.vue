<template>
  <div class="key-share-chart">
    <h3>Key Share Size Comparison</h3>
    <p v-if="!entries.length" class="empty">No key share data available.</p>
    <Bar v-else :data="chartData" :options="chartOptions" />
    <div class="legend">
      <span class="dot classical"></span> Classical &nbsp;
      <span class="dot pqc"></span> PQC &nbsp;
      <span class="dot hybrid"></span> Hybrid
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import {
  Chart as ChartJS,
  Title,
  Tooltip,
  Legend,
  BarElement,
  CategoryScale,
  LinearScale,
} from 'chart.js'

ChartJS.register(Title, Tooltip, Legend, BarElement, CategoryScale, LinearScale)

const props = defineProps({ record: { type: Object, required: true } })

const COLOR_CLASSICAL = 'rgba(160,160,160,0.8)'
const COLOR_PQC = 'rgba(31,119,180,0.8)'
const COLOR_HYBRID = 'rgba(23,190,207,0.8)'

const pqcKeywords = ['mlkem', 'kyber', 'dilithium', 'falcon', 'sphincs', 'ntru', 'saber']
const classicalKeywords = [
  'x25519',
  'x448',
  'secp256r1',
  'secp384r1',
  'secp521r1',
  'prime256v1',
  'p256',
  'p384',
  'p521',
  'ffdhe',
]

function normalizeGroupName(name) {
  return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function classifyGroup(name) {
  const normalized = normalizeGroupName(name)
  const hasClassical = classicalKeywords.some(k => normalized.includes(k))
  const hasPqc = pqcKeywords.some(k => normalized.includes(k))

  if (hasClassical && hasPqc) return 'hybrid'
  if (hasPqc) return 'pqc'
  return 'classical'
}

function colorForClass(cls) {
  if (cls === 'hybrid') return COLOR_HYBRID
  if (cls === 'pqc') return COLOR_PQC
  return COLOR_CLASSICAL
}

const entries = computed(() => {
  const ks = props.record?.client_hello?.key_shares || []
  return ks.map(k => ({
    name: k.group_name || `group_${k.group_id}`,
    size: k.key_exchange_length || 0,
    cls: classifyGroup(k.group_name || ''),
  }))
})

const chartData = computed(() => ({
  labels: entries.value.map(e => e.name),
  datasets: [
    {
      label: 'Key Exchange Length (bytes)',
      data: entries.value.map(e => e.size),
      backgroundColor: entries.value.map(e => colorForClass(e.cls)),
      borderColor: entries.value.map(e => colorForClass(e.cls).replace('0.8', '1')),
      borderWidth: 1,
    },
  ],
}))

const chartOptions = {
  indexAxis: 'y',
  responsive: true,
  plugins: {
    legend: { display: false },
    title: { display: false },
    tooltip: {
      callbacks: {
        label: (ctx) => ` ${ctx.parsed.x} bytes`,
      },
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Key Exchange Length (bytes)' },
      beginAtZero: true,
    },
    y: {
      title: { display: true, text: 'Group' },
    },
  },
}
</script>

<style scoped>
.key-share-chart h3 { margin-bottom: 0.75rem; font-size: 1rem; color: #333; }
.empty { color: #888; font-style: italic; }
.legend { margin-top: 0.75rem; font-size: 0.85rem; color: #555; display: flex; align-items: center; gap: 0.2rem; }
.dot { display: inline-block; width: 12px; height: 12px; border-radius: 2px; }
.dot.classical { background: rgb(160,160,160); }
.dot.pqc { background: rgb(31,119,180); }
.dot.hybrid { background: rgb(23,190,207); }
</style>
