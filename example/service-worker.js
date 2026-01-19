addEventListener('push', ev => {
  // https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/showNotification
  const data = ev.data.json()
  console.log('push event', ev, data)
  ev.waitUntil(self.registration.showNotification(data.title, data))
})

// This event is not supported by all browsers, notably iOS/Safari:
// https://caniuse.com/mdn-api_serviceworkerglobalscope_notificationclick_event
addEventListener('notificationclick', ev => {
  console.log('notificationclick', ev)
  ev.notification.close()
  ev.waitUntil((async () => {
    // focus existing client, otherwise open new window
    const clientList = await clients.matchAll()
    if (clientList.length > 0) return clientList[0].focus()
    return clients.openWindow(ev.notification.data?.url ?? '/')
  })())
})

addEventListener('install', () => {
  // Makes the Service Worker immediately active.
  skipWaiting()
})
