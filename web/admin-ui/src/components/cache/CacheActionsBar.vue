<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-4 flex flex-wrap items-center gap-3">
    <!-- Purge by Tag -->
    <div class="flex items-center gap-2">
      <input
        v-model="tagInput"
        :placeholder="$t('cache.purgeTag')"
        class="text-sm border border-gray-300 rounded-md px-3 py-1.5 w-44 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
      <button
        @click="doPurgeTag"
        :disabled="!tagInput.trim() || loading"
        class="text-sm font-medium text-white bg-orange-500 hover:bg-orange-600 disabled:opacity-50 rounded-md px-3 py-1.5"
      >{{ $t('cache.purgeTag') }}</button>
    </div>

    <!-- Purge by Route -->
    <div class="flex items-center gap-2">
      <input
        v-model="routeInput"
        :placeholder="$t('cache.purgeRoute')"
        class="text-sm border border-gray-300 rounded-md px-3 py-1.5 w-44 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
      <button
        @click="doPurgeRoute"
        :disabled="!routeInput.trim() || loading"
        class="text-sm font-medium text-white bg-orange-500 hover:bg-orange-600 disabled:opacity-50 rounded-md px-3 py-1.5"
      >{{ $t('cache.purgeRoute') }}</button>
    </div>

    <div class="ml-auto">
      <button
        @click="confirmFlush = true"
        :disabled="loading"
        class="text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-md px-4 py-1.5"
      >{{ $t('cache.flushAll') }}</button>
    </div>

    <!-- Flush confirmation modal -->
    <teleport to="body">
      <div v-if="confirmFlush" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
        <div class="bg-white rounded-xl shadow-xl p-6 max-w-sm w-full mx-4">
          <p class="text-sm text-gray-700 mb-4">{{ $t('cache.confirmFlush') }}</p>
          <div class="flex justify-end gap-3">
            <button @click="confirmFlush = false" class="text-sm text-gray-600 hover:text-gray-900">{{ $t('common.cancel') }}</button>
            <button
              @click="doFlush"
              class="text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md px-4 py-1.5"
            >{{ $t('cache.flushAll') }}</button>
          </div>
        </div>
      </div>
    </teleport>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

defineProps<{ loading: boolean }>()
const emit = defineEmits<{
  (e: 'purge-tag', tag: string): void
  (e: 'purge-route', route: string): void
  (e: 'flush-all'): void
}>()

const tagInput = ref('')
const routeInput = ref('')
const confirmFlush = ref(false)

function doPurgeTag() {
  const t = tagInput.value.trim()
  if (!t) return
  emit('purge-tag', t)
  tagInput.value = ''
}

function doPurgeRoute() {
  const r = routeInput.value.trim()
  if (!r) return
  emit('purge-route', r)
  routeInput.value = ''
}

function doFlush() {
  confirmFlush.value = false
  emit('flush-all')
}
</script>
