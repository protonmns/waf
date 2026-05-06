<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 space-y-4">
    <h3 class="text-sm font-semibold text-gray-700">{{ $t('cache.backendInfo') }}</h3>

    <!-- Mode / Version / Circuit breaker -->
    <div class="flex flex-wrap items-center gap-3 text-sm">
      <span class="text-gray-500">{{ $t('cache.mode') }}:</span>
      <span class="font-semibold text-gray-900 capitalize">{{ info.backend ?? '—' }}</span>

      <span v-if="info.version" class="text-gray-500 ml-2">{{ $t('cache.version') }}:</span>
      <span v-if="info.version" class="font-mono text-gray-800 text-xs bg-gray-100 px-2 py-0.5 rounded">{{ info.version }}</span>

      <span v-if="info.circuit_breaker !== undefined" class="text-gray-500 ml-2">{{ $t('cache.circuitBreaker') }}:</span>
      <span
        v-if="info.circuit_breaker !== undefined"
        :class="circuitClass"
        class="text-xs font-semibold px-2 py-0.5 rounded-full"
      >● {{ info.circuit_breaker }}</span>
    </div>

    <!-- Memory bar (only for Valkey backends) -->
    <div v-if="memPct !== null" class="space-y-1">
      <div class="flex justify-between text-xs text-gray-500">
        <span>{{ $t('cache.memoryUsed') }}</span>
        <span>{{ fmtBytes(info.memory_used_bytes) }} / {{ fmtBytes(info.memory_max_bytes) }} ({{ memPct }}%)</span>
      </div>
      <div class="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          :style="{ width: `${memPct}%` }"
          :class="memPct > 80 ? 'bg-red-500' : memPct > 60 ? 'bg-orange-400' : 'bg-blue-500'"
          class="h-full rounded-full transition-all duration-500"
        ></div>
      </div>
    </div>

    <!-- Cluster nodes table -->
    <div v-if="info.nodes && info.nodes.length" class="overflow-x-auto">
      <table class="w-full text-xs">
        <thead>
          <tr class="text-gray-500 border-b">
            <th class="text-left pb-1 font-medium">{{ $t('cache.nodes') }}</th>
            <th class="text-left pb-1 font-medium">{{ $t('cache.role') }}</th>
            <th class="text-left pb-1 font-medium">{{ $t('cache.slots') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="node in info.nodes" :key="node.addr" class="border-b last:border-0">
            <td class="py-1 font-mono text-gray-700">{{ node.addr }}</td>
            <td class="py-1">
              <span
                :class="node.role === 'master' ? 'bg-blue-50 text-blue-700' : 'bg-gray-100 text-gray-600'"
                class="px-1.5 py-0.5 rounded text-xs font-medium"
              >{{ node.role }}</span>
            </td>
            <td class="py-1 text-gray-600">{{ node.slots }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface NodeInfo { addr: string; role: string; slots: string }
interface BackendInfo {
  backend?: string
  version?: string
  circuit_breaker?: string
  memory_used_bytes?: number
  memory_max_bytes?: number
  nodes?: NodeInfo[]
}

const props = defineProps<{ info: BackendInfo }>()

const memPct = computed(() => {
  const used = props.info.memory_used_bytes
  const max = props.info.memory_max_bytes
  if (!used || !max || max === 0) return null
  return Math.min(100, (used / max) * 100).toFixed(1)
})

const circuitClass = computed(() => {
  switch (props.info.circuit_breaker) {
    case 'closed': return 'bg-green-100 text-green-700'
    case 'half_open': return 'bg-yellow-100 text-yellow-700'
    case 'open': return 'bg-red-100 text-red-700'
    default: return 'bg-gray-100 text-gray-600'
  }
})

function fmtBytes(n?: number): string {
  if (!n) return '0 B'
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} GB`
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}
</script>
