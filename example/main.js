function showMsg(msg) {
  document.getElementById('msg').innerText = msg
}

window.addEventListener('unhandledrejection', ev => showMsg(ev.reason))
window.addEventListener('error', ev => showMsg(ev.error))

async function setBodyClassFromPermission() {
  const registration = await navigator.serviceWorker.register(
    '/service-worker.js',
    { updateViaCache: 'none' },
  )
  if (!registration.pushManager) {
    document.body.className = 'push-unavailable'
    return
  }
  const permissionState = await registration.pushManager.permissionState({
    userVisibleOnly: true,
  })
  document.body.className = `push-${permissionState}`
}

document.querySelector('#send-push').addEventListener('click', async () => {
  const applicationServerKey = Uint8Array.fromBase64(
    document.querySelector('[data-vapid-public-key]').dataset.vapidPublicKey,
    { alphabet: 'base64url' },
  )
  const registration = await navigator.serviceWorker.getRegistration()
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey,
  })
  console.log('push subscription', subscription)
  const res = await fetch('/push', {
    method: 'post',
    body: JSON.stringify(subscription),
  })
  if (res.ok) {
    showMsg(
      'Scheduled push notification. Check server logs for errors if any.',
    )
  } else showMsg('Error scheduling push: ' + await res.text())
})

document.querySelector('#unsubscribe').addEventListener('click', async () => {
  const registration = await navigator.serviceWorker.getRegistration()
  const subscription = await registration.pushManager.getSubscription()
  if (!subscription) {
    showMsg('No existing subscription.')
    return
  }
  await subscription.unsubscribe()
  showMsg('Successfully unsubscribed.')
  setBodyClassFromPermission()
})

setBodyClassFromPermission()
