<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
    <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('cache.topRoutes') }}</h3>
    <div v-if="routes.length" class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-xs text-gray-500 border-b">
            <th class="text-left pb-2 font-medium">Route</th>
            <th class="text-right pb-2 font-medium">{{ $t('cache.hits') }}</th>
            <th class="text-right pb-2 font-medium">{{ $t('cache.entries') }}</th>
            <th class="pb-2"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in routes" :key="r.route_id" class="border-b last:border-0 hover:bg-gray-50">
            <td class="py-2 font-mono text-xs text-gray-700 max-w-[180px] truncate">{{ r.route_id }}</td>
            <td class="py-2 text-right tabular-nums text-gray-900">{{ fmtNum(r.hits) }}</td>
            <td class="py-2 text-right tabular-nums text-gray-600 text-xs">{{ fmtNum(r.entry_count) }}</td>
            <td class="py-2 text-right">
              <button
                @click="$emit('purge-route', r.route_id)"
                class="text-xs text-red-600 hover:text-red-800 font-medium"
              >{{ $t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="text-sm text-gray-400 text-center py-6">{{ $t('common.noData') }}</div>
  </div>
</template>

<script setup lang="ts">
interface RouteRow { route_id: string; hits: number; entry_count: number }
defineProps<{ routes: RouteRow[] }>()
defineEmits<{ (e: 'purge-route', id: string): void }>()

function fmtNum(n: number): string {
  if (!n && n !== 0) return '—'
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}
</script>
