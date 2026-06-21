<template>
  <div class="handshake-flow">
    <h3>TLS Handshake Sequence Diagram</h3>
    <svg :width="svgWidth" :height="svgHeight" class="flow-svg">
      <!-- Column headers -->
      <rect x="10" y="10" width="160" height="36" rx="6" fill="#1a237e" />
      <text x="90" y="33" text-anchor="middle" fill="#fff" font-weight="bold" font-size="14">Client</text>
      <rect :x="svgWidth - 170" y="10" width="160" height="36" rx="6" fill="#1a237e" />
      <text :x="svgWidth - 90" y="33" text-anchor="middle" fill="#fff" font-weight="bold" font-size="14">Server</text>

      <!-- Lifelines -->
      <line x1="90" y1="46" :x2="90" :y2="svgHeight - 10" stroke="#aaa" stroke-dasharray="6,4" stroke-width="1.5"/>
      <line :x1="svgWidth - 90" y1="46" :x2="svgWidth - 90" :y2="svgHeight - 10" stroke="#aaa" stroke-dasharray="6,4" stroke-width="1.5"/>

      <!-- ClientHello arrow -->
      <g>
        <line x1="90" :y1="steps.clientHello.y" :x2="svgWidth - 90" :y2="steps.clientHello.y"
          :stroke="isPqc ? pqcColor : defaultColor" stroke-width="2" marker-end="url(#arrow)" />
        <text x="50%" :y="steps.clientHello.y - 6" text-anchor="middle"
          :fill="isPqc ? pqcColor : '#333'" font-weight="bold" font-size="13">ClientHello</text>
        <foreignObject x="100" :y="steps.clientHello.y + 8" :width="svgWidth * 0.45 - 20" height="120">
          <div xmlns="http://www.w3.org/1999/xhtml" class="anno">
            <span v-if="sni"><b>SNI:</b> {{ sni }}<br/></span>
            <span v-if="supportedGroups.length"><b>Groups:</b>
              <span v-for="g in supportedGroups" :key="g" :class="groupClass(g)" class="group-tag">{{ g }}</span>
            </span>
          </div>
        </foreignObject>
      </g>

      <!-- ServerHello arrow -->
      <g>
        <line :x1="svgWidth - 90" :y1="steps.serverHello.y" x2="90" :y2="steps.serverHello.y"
          :stroke="isPqc ? pqcColor : defaultColor" stroke-width="2" marker-end="url(#arrow)" />
        <text x="50%" :y="steps.serverHello.y - 6" text-anchor="middle"
          :fill="isPqc ? pqcColor : '#333'" font-weight="bold" font-size="13">ServerHello</text>
        <foreignObject :x="svgWidth * 0.5 + 10" :y="steps.serverHello.y + 8" :width="svgWidth * 0.45 - 20" height="80">
          <div xmlns="http://www.w3.org/1999/xhtml" class="anno anno-right">
            <span v-if="negotiatedSuite"><b>Suite:</b> {{ negotiatedSuite }}<br/></span>
            <span v-if="selectedGroup"><b>Group:</b>
              <span :class="groupClass(selectedGroup)" class="group-tag">{{ selectedGroup }}</span><br/>
            </span>
            <span v-if="isPqc" class="badge pqc">PQC</span>
            <span v-if="isHybrid" class="badge hybrid">Hybrid</span>
          </div>
        </foreignObject>
      </g>

      <!-- Certificate arrow -->
      <g>
        <text x="50%" :y="steps.serverHello.y + 120" text-anchor="middle" fill="#999" font-size="12" font-style="italic">…</text>
        <text x="50%" :y="steps.serverHello.y + 140" text-anchor="middle" fill="#999" font-size="11">(handshake continues)</text>
      </g>

      <!-- Arrow markers -->
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#555" />
        </marker>
        <marker id="arrowL" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#555" />
        </marker>
      </defs>
    </svg>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ record: { type: Object, required: true } })

const svgWidth = 700
const svgHeight = 380

const pqcColor = '#1f77b4'
const hybridColor = '#17becf'
const defaultColor = '#555'

const isPqc = computed(() => props.record?.server_hello?.is_pqc)
const isHybrid = computed(() => props.record?.server_hello?.is_hybrid)
const negotiatedSuite = computed(() => props.record?.server_hello?.negotiated_cipher_suite)
const selectedGroup = computed(() => props.record?.server_hello?.selected_group)
const supportedGroups = computed(() => props.record?.client_hello?.supported_groups || [])
const sni = computed(() => props.record?.client_hello?.extensions?.server_name)

const pqcKeywords = ['mlkem', 'kyber', 'dilithium', 'falcon', 'sphincs', 'ntru']
const hybridKeywords = [
  'x25519mlkem',
  'x25519kyber',
  'p256mlkem',
  'p384mlkem',
  'secp256r1mlkem',
  'secp384r1mlkem',
]

function groupClass(name) {
  const lower = (name || '').toLowerCase()
  if (hybridKeywords.some(k => lower.includes(k))) return 'hybrid'
  if (pqcKeywords.some(k => lower.includes(k))) return 'pqc'
  return 'classical'
}

const steps = {
  clientHello:    { y: 90 },
  serverHello:    { y: 260 },
}
</script>

<style scoped>
.handshake-flow { overflow-x: auto; }
h3 { margin-bottom: 1rem; font-size: 1rem; color: #333; }
.flow-svg { display: block; }
.anno { font-size: 11px; line-height: 1.5; color: #333; background: #f0f4ff; border: 1px solid #c5cae9; border-radius: 4px; padding: 4px 6px; }
.anno-right { text-align: left; }
.group-tag { display: inline-block; padding: 1px 5px; border-radius: 3px; margin: 1px; font-size: 10px; }
.group-tag.hybrid { background: #e0f7fa; color: #00695c; border: 1px solid #80cbc4; }
.group-tag.pqc { background: #e3f2fd; color: #0d47a1; border: 1px solid #90caf9; }
.group-tag.classical { background: #f5f5f5; color: #555; border: 1px solid #ddd; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 10px; font-weight: bold; margin-right: 3px; }
.badge.pqc { background: #1f77b4; color: #fff; }
.badge.hybrid { background: #17becf; color: #fff; }
</style>
