import { useEffect } from 'react'
import Lenis from 'lenis'
import 'lenis/dist/lenis.css'

// Turns stepped mouse-wheel scrolling into one continuous glide, and animates in-page links.
// The page still scrolls natively underneath, so sticky sections and keyboard scrolling keep working.
export function useSmoothScroll() {
  useEffect(() => {
    // A demo should always open on the hero, whatever the last visit scrolled to.
    history.scrollRestoration = 'manual'
    window.scrollTo(0, 0)
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const lenis = new Lenis({ lerp: 0.06, wheelMultiplier: 0.8, anchors: { offset: -72 } })
    let raf = requestAnimationFrame(function tick(time) {
      lenis.raf(time)
      raf = requestAnimationFrame(tick)
    })
    return () => {
      cancelAnimationFrame(raf)
      lenis.destroy()
    }
  }, [])
}
