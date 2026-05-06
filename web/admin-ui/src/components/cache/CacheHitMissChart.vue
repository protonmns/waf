<template>
  <div class="w-full">
    <svg v-if="points.length" :viewBox="`0 0 ${W} ${H}`" class="w-full h-48" preserveAspectRatio="none">
      <!-- Y grid -->
      <g stroke="#f1f5f9" stroke-width="1">
        <line v-for="i in 4" :key="i" :x1="0" :y1="(i * H / 4)" :x2="W" :y2="(i * H / 4)" />
      </g>
      <!-- Hits area + line -->
      <path :d="hitsArea" fill="#22c55e" fill-opacity="0.12" />
      <path :d="hitsLine" fill="none" stroke="#22c55e" stroke-width="2" />
      <!-- Misses line -->
      <path :d="missesLine" fill="none" stroke="#ef4444" stroke-width="2" />
      <!-- Dots -->
      <circle v-for="(p, i) in points" :key="`h${i}`" :cx="x(i)" :cy="y(p.hits)" r="2.5" fill="#22c55e" />
      <circle v-for="(p, i) in points" :key="`m${i}`" :cx="x(i)" :cy="y(p.misses)" r="2.5" fill="#ef4444" />
    </svg>
    <div v-else class="h-48 flex items-center justify-center text-sm text-gray-400">
      {{ $t('common.noData') }}
    </div>
    <!-- Legend + x-axis -->
    <div class="flex items-center justify-between mt-2 text-xs text-gray-400 px-1">
      <span v-if="points.length">{{ fmtTime(points[0].ts) }}</span>
      <div class="flex items-center gap-3">
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-0.5 bg-green-500"></span>{{ $t('cache.hits') }}</span>
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-0.5 bg-red-500"></span>{{ $t('cache.misses') }}</span>
      </div>
      <span v-if="points.length">{{ fmtTime(points[points.length - 1].ts) }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface TsBucket { ts: string; hits: number; misses: number }
const props = defineProps<{ series: TsBucket[] }>()

const W = 1000
const H = 180
const PAD = 10

const points = computed(() => props.series ?? [])

const maxY = computed(() => {
  if (!points.value.length) return 1
  const m = Math.max(...points.value.flatMap(p => [Number(p.hits), Number(p.misses)]), 1)
  return Math.ceil(m * 1.1)
})

function x(i: number): number {
  const n = points.value.length
  if (n <= 1) return W / 2
  return PAD + (i / (n - 1)) * (W - 2 * PAD)
}
function y(v: number): number {
  return H - PAD - (Number(v) / maxY.value) * (H - 2 * PAD)
}

function lineD(vals: number[]): string {
  return vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
}

const hitsLine = computed(() => lineD(points.value.map(p => p.hits)))
const missesLine = computed(() => lineD(points.value.map(p => p.misses)))
const hitsArea = computed(() => {
  const pts = points.value
  if (!pts.length) return ''
  const line = lineD(pts.map(p => p.hits))
  return `${line} L${x(pts.length - 1).toFixed(1)},${H - PAD} L${PAD},${H - PAD} Z`
})

function fmtTime(ts: string): string {
  const d = new Date(ts)
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
}
</script>
