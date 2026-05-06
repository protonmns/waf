<template>
  <Layout>
    <div class="p-6 space-y-6">
      <!-- Header -->
      <div class="flex items-start justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('cache.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('cache.subtitle') }}</p>
        </div>
        <button
          @click="refreshAll"
          :disabled="loading"
          class="inline-flex items-center gap-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md px-3 py-1.5 hover:bg-gray-50 disabled:opacity-50"
        >
          <RefreshCw :class="loading ? 'animate-spin' : ''" class="w-4 h-4" />
          {{ $t('common.refresh') }}
        </button>
      </div>

      <!-- KPI row -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          :label="$t('cache.hitRatio')"
          :value="fmtPct(stats.hit_ratio)"
          :icon="Percent"
          color="green"
        />
        <KpiCard
          :label="$t('cache.entries')"
          :value="fmtNum(stats.entry_count)"
          :icon="Database"
          color="blue"
        />
        <KpiCard
          :label="$t('cache.memoryUsed')"
          :value="fmtBytes(stats.memory_used_bytes)"
          :icon="HardDrive"
          color="purple"
        />
        <KpiCard
          :label="$t('cache.opsPerSec')"
          :value="fmtNum(stats.valkey_ops_per_sec)"
          :icon="Zap"
          color="orange"
        />
      </div>

      <!-- Hit/Miss timeline chart -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('cache.hitMissTimeline') }}</h3>
        <CacheHitMissChart :series="timeseries" />
      </div>

      <!-- Top routes + Tag donut (2 cols) -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <CacheTopRoutesTable :routes="topRoutes" @purge-route="handlePurgeRoute" />
        <CacheTagDonut :tags="tagItems" />
      </div>

      <!-- Backend info (only shown for non-memory backends) -->
      <CacheBackendCard :info="backend" />

      <!-- Actions bar -->
      <CacheActionsBar
        :loading="actionLoading"
        @purge-tag="handlePurgeTag"
        @purge-route="handlePurgeRoute"
        @flush-all="handleFlushAll"
      />

      <!-- Toast notifications -->
      <teleport to="body">
        <transition name="fade">
          <div
            v-if="toast"
            class="fixed bottom-6 right-6 bg-gray-900 text-white text-sm rounded-lg px-4 py-2.5 shadow-lg z-50"
          >{{ toast }}</div>
        </transition>
      </teleport>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { RefreshCw, Percent, Database, HardDrive, Zap } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import KpiCard from '../components/KpiCard.vue'
import CacheHitMissChart from '../components/cache/CacheHitMissChart.vue'
import CacheTopRoutesTable from '../components/cache/CacheTopRoutesTable.vue'
import CacheTagDonut from '../components/cache/CacheTagDonut.vue'
import CacheBackendCard from '../components/cache/CacheBackendCard.vue'
import CacheActionsBar from '../components/cache/CacheActionsBar.vue'
import { cacheApi } from '../api/index'

const { t } = useI18n()

// ─── State ────────────────────────────────────────────────────────────────────
const loading = ref(false)
const actionLoading = ref(false)
const toast = ref<string | null>(null)

const stats = ref<Record<string, any>>({})
const backend = ref<Record<string, any>>({})
const timeseries = ref<{ ts: string; hits: number; misses: number }[]>([])
const topRoutes = ref<{ route_id: string; hits: number; entry_count: number }[]>([])
const tagItems = ref<{ tag: string; count: number }[]>([])

// ─── Polling timers ───────────────────────────────────────────────────────────
let timerStats: ReturnType<typeof setInterval>
let timerBackend: ReturnType<typeof setInterval>
let timerTs: ReturnType<typeof setInterval>
let timerRoutes: ReturnType<typeof setInterval>
let timerTags: ReturnType<typeof setInterval>

// ─── Data loaders ─────────────────────────────────────────────────────────────
async function loadStats() {
  const r = await cacheApi.stats().catch(() => null)
  if (r) stats.value = r.data
}

async function loadBackend() {
  const r = await cacheApi.backend().catch(() => null)
  if (r) backend.value = r.data
}

async function loadTimeseries() {
  const r = await cacheApi.timeseries(60).catch(() => null)
  if (r) timeseries.value = r.data
}

async function loadTopRoutes() {
  const r = await cacheApi.topRoutes(20).catch(() => null)
  if (r) topRoutes.value = r.data
}

async function loadTags() {
  const r = await cacheApi.tags().catch(() => null)
  if (r) tagItems.value = r.data?.tags ?? []
}

async function refreshAll() {
  loading.value = true
  await Promise.all([loadStats(), loadBackend(), loadTimeseries(), loadTopRoutes(), loadTags()])
  loading.value = false
}

// ─── Actions ──────────────────────────────────────────────────────────────────
function showToast(msg: string) {
  toast.value = msg
  setTimeout(() => { toast.value = null }, 3000)
}

async function handlePurgeTag(tag: string) {
  actionLoading.value = true
  const r = await cacheApi.purgeTag(tag).catch(() => null)
  actionLoading.value = false
  if (r) {
    showToast(t('cache.purged', { n: r.data?.purged ?? 0 }))
    await loadStats()
  }
}

async function handlePurgeRoute(routeId: string) {
  actionLoading.value = true
  const r = await cacheApi.purgeRoute(routeId).catch(() => null)
  actionLoading.value = false
  if (r) {
    showToast(t('cache.purged', { n: r.data?.purged ?? 0 }))
    await Promise.all([loadStats(), loadTopRoutes()])
  }
}

async function handleFlushAll() {
  actionLoading.value = true
  await cacheApi.flush().catch(() => null)
  actionLoading.value = false
  showToast(t('cache.flushAll'))
  await loadStats()
}

// ─── Formatters ───────────────────────────────────────────────────────────────
function fmtPct(v?: number): string {
  if (v === undefined || v === null) return '—'
  return `${(Number(v) * 100).toFixed(1)}%`
}

function fmtNum(v?: number): string {
  if (v === undefined || v === null) return '—'
  const n = Number(v)
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}

function fmtBytes(n?: number): string {
  if (!n) return '—'
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} GB`
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────
onMounted(async () => {
  await refreshAll()
  timerStats = setInterval(loadStats, 5_000)
  timerBackend = setInterval(loadBackend, 15_000)
  timerTs = setInterval(loadTimeseries, 60_000)
  timerRoutes = setInterval(loadTopRoutes, 30_000)
  timerTags = setInterval(loadTags, 30_000)
})

onUnmounted(() => {
  clearInterval(timerStats)
  clearInterval(timerBackend)
  clearInterval(timerTs)
  clearInterval(timerRoutes)
  clearInterval(timerTags)
})
</script>

<style scoped>
.fade-enter-active, .fade-leave-active { transition: opacity 0.3s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
