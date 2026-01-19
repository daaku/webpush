function showMsg(msg) {
  document.getElementById('msg').innerText = msg
}

document.querySelector('#send-push').addEventListener('click', async () => {
  try {
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
  } catch (err) {
    showMsg(err)
  }
})

document.querySelector('#unsubscribe').addEventListener('click', async () => {
  try {
    const registration = await navigator.serviceWorker.getRegistration()
    const subscription = await registration.pushManager.getSubscription()
    if (!subscription) {
      showMsg('No existing subscription.')
      return
    }
    await subscription.unsubscribe()
    showMsg('Successfully unsubscribed.')
  } catch (err) {
    showMsg(err)
  }
})
;(async () => {
  try {
    const registration = await navigator.serviceWorker.register(
      '/service-worker.js',
      { updateViaCache: 'none' },
    )
    const permissionState = await registration.pushManager.permissionState({
      userVisibleOnly: true,
    })
    document.body.classList.add(`push-${permissionState}`)
  } catch (err) {
    showMsg(err)
  }
})()
