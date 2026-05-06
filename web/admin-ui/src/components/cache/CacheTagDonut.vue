<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
    <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('cache.tagDistribution') }}</h3>

    <div v-if="slices.length" class="flex items-center gap-6">
      <!-- SVG Donut -->
      <svg viewBox="0 0 80 80" class="w-24 h-24 shrink-0">
        <circle
          v-for="(s, i) in slices" :key="i"
          cx="40" cy="40" r="28"
          fill="none" :stroke="s.color" stroke-width="12"
          :stroke-dasharray="`${s.dash} ${circumference - s.dash}`"
          :stroke-dashoffset="-s.offset"
          style="transition: stroke-dasharray 0.5s ease"
        />
        <text x="40" y="44" text-anchor="middle" class="text-xs font-bold" font-size="10" fill="#374151">
          {{ total }}
        </text>
      </svg>

      <!-- Legend -->
      <ul class="space-y-1 text-xs min-w-0 flex-1">
        <li v-for="(s, i) in slices" :key="i" class="flex items-center gap-2 truncate">
          <span :style="{ background: s.color }" class="inline-block w-2.5 h-2.5 rounded-sm shrink-0"></span>
          <span class="truncate text-gray-700">{{ s.label }}</span>
          <span class="ml-auto tabular-nums text-gray-500 shrink-0">{{ s.pct }}%</span>
        </li>
      </ul>
    </div>

    <div v-else class="text-sm text-gray-400 text-center py-6">{{ $t('common.noData') }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface TagItem { tag: string; count: number }
const props = defineProps<{ tags: TagItem[] }>()

const COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16']
const circumference = 2 * Math.PI * 28

const total = computed(() => props.tags.reduce((s, t) => s + t.count, 0))

const slices = computed(() => {
  const items = [...props.tags].sort((a, b) => b.count - a.count).slice(0, 8)
  const sum = items.reduce((s, t) => s + t.count, 0) || 1
  let offset = 0
  return items.map((t, i) => {
    const pct = (t.count / sum) * 100
    const dash = (t.count / sum) * circumference
    const s = { label: t.tag, color: COLORS[i % COLORS.length], dash, offset, pct: pct.toFixed(1) }
    offset += dash
    return s
  })
})
</script>
