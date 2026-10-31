import gsap from 'gsap'

// The way into the dashboard. Light floods out from the exact point that was clicked, the route changes
// while the screen is covered, then a hole opens from that same point to show the new page.
export function openPortal(go: () => void, x: number, y: number) {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    go()
    return
  }
  const cv = document.createElement('canvas')
  cv.setAttribute('aria-hidden', 'true')
  cv.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;z-index:100'
  document.body.appendChild(cv)
  // Half resolution is plenty for soft gradients, and keeps the fill fast on a big window.
  const w = (cv.width = Math.ceil(window.innerWidth / 2))
  const h = (cv.height = Math.ceil(window.innerHeight / 2))
  const px = x / 2
  const py = y / 2
  const ctx = cv.getContext('2d')!
  const far = Math.max(Math.hypot(px, py), Math.hypot(w - px, py), Math.hypot(px, h - py), Math.hypot(w - px, h - py))
  const SOFT = 70
  const s = { reach: 1, hole: 0, dim: 0 }

  const draw = () => {
    ctx.globalCompositeOperation = 'source-over'
    ctx.clearRect(0, 0, w, h)
    ctx.fillStyle = `rgb(2 5 15 / ${s.dim})`
    ctx.fillRect(0, 0, w, h)
    const light = ctx.createRadialGradient(px, py, 0, px, py, s.reach)
    light.addColorStop(0, 'rgb(255 255 255)')
    light.addColorStop(0.18, 'rgb(217 232 255)')
    light.addColorStop(0.45, 'rgb(61 139 255)')
    light.addColorStop(0.72, 'rgb(61 139 255 / 0.45)')
    light.addColorStop(1, 'rgb(61 139 255 / 0)')
    ctx.fillStyle = light
    ctx.fillRect(0, 0, w, h)
    if (s.hole > 0.5) {
      ctx.globalCompositeOperation = 'destination-out'
      const hole = ctx.createRadialGradient(px, py, 0, px, py, s.hole)
      hole.addColorStop(Math.max(0, (s.hole - SOFT) / s.hole), 'rgb(0 0 0)')
      hole.addColorStop(1, 'rgb(0 0 0 / 0)')
      ctx.fillStyle = hole
      ctx.fillRect(0, 0, w, h)
    }
  }

  gsap.to(s, {
    reach: far / 0.6,
    dim: 0.7,
    duration: 0.6,
    ease: 'power2.in',
    onUpdate: draw,
    onComplete: () => {
      go()
      // Wait for the dashboard to exist, so the hole never opens onto a blank page.
      const started = performance.now()
      const ready = () => {
        if (document.querySelector('.dash') || performance.now() - started > 2000) {
          gsap.to(s, { hole: far + SOFT, duration: 1, ease: 'power2.inOut', onUpdate: draw, onComplete: () => cv.remove() })
        } else {
          requestAnimationFrame(ready)
        }
      }
      ready()
    },
  })
}
