import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'

type Props = {
  to?: string
  href?: string
  variant?: 'primary' | 'line'
  arrow?: boolean
  className?: string
  children: string
}

// GSAP hover, three effects together:
// 1. a white circle grows out of the exact point the pointer entered (and shrinks to where it left)
// 2. the letters roll upward one after another
// 3. the whole button leans magnetically towards the pointer, then springs back
export function FxButton({ to, href, variant = 'primary', arrow = false, className = '', children }: Props) {
  const root = useRef<HTMLAnchorElement>(null)

  useEffect(() => {
    const el = root.current!
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    if (!window.matchMedia('(hover: hover)').matches) return

    const fill = el.querySelector<HTMLElement>('.fx-fill')!
    const label = el.querySelector<HTMLElement>('.fx-label')!
    const icon = el.querySelector<HTMLElement>('.fx-arrow')
    const chars = el.querySelectorAll('.fx-char')
    const moveX = gsap.quickTo(el, 'x', { duration: 0.5, ease: 'power3.out' })
    const moveY = gsap.quickTo(el, 'y', { duration: 0.5, ease: 'power3.out' })

    const at = (e: PointerEvent) => {
      const box = el.getBoundingClientRect()
      return { x: e.clientX - box.left, y: e.clientY - box.top, w: box.width, h: box.height }
    }
    const enter = (e: PointerEvent) => {
      const { x, y, w, h } = at(e)
      gsap.killTweensOf([fill, chars, label])
      gsap.set(fill, { left: x, top: y })
      gsap.fromTo(fill, { scale: 0 }, { scale: Math.hypot(w, h) / 5, duration: 0.55, ease: 'power3.out' })
      gsap.to(label, { color: getComputedStyle(el).getPropertyValue('--fx-text').trim(), duration: 0.22 })
      gsap.fromTo(chars, { yPercent: 0 }, { yPercent: -100, duration: 0.42, ease: 'power3.inOut', stagger: 0.014 })
      if (icon) gsap.fromTo(icon, { x: 0 }, { keyframes: [{ x: 18, opacity: 0, duration: 0.18, ease: 'power2.in' }, { x: -14, duration: 0 }, { x: 0, opacity: 1, duration: 0.3, ease: 'power3.out' }] })
    }
    const move = (e: PointerEvent) => {
      const { x, y, w, h } = at(e)
      moveX((x - w / 2) * 0.22)
      moveY((y - h / 2) * 0.32)
    }
    const leave = (e: PointerEvent) => {
      const { x, y } = at(e)
      gsap.killTweensOf([fill, chars, label])
      gsap.set(fill, { left: x, top: y })
      gsap.to(fill, { scale: 0, duration: 0.45, ease: 'power3.inOut' })
      gsap.to(label, { color: '', duration: 0.3, delay: 0.1, clearProps: 'color' })
      gsap.to(chars, { yPercent: 0, duration: 0.42, ease: 'power3.inOut', stagger: 0.01 })
      gsap.to(el, { x: 0, y: 0, duration: 0.9, ease: 'elastic.out(1, 0.45)', overwrite: true })
    }
    el.addEventListener('pointerenter', enter)
    el.addEventListener('pointermove', move)
    el.addEventListener('pointerleave', leave)
    return () => {
      el.removeEventListener('pointerenter', enter)
      el.removeEventListener('pointermove', move)
      el.removeEventListener('pointerleave', leave)
      gsap.killTweensOf([el, fill, label, chars])
    }
  }, [])

  const inner = (
    <>
      <span aria-hidden className="fx-fill" />
      <span className="fx-label">
        <span className="sr-only">{children}</span>
        <span aria-hidden className="fx-chars">
          {children.split('').map((c, i) => (
            <span key={i} className="fx-char" data-c={c}>{c === ' ' ? ' ' : c}</span>
          ))}
        </span>
        {arrow && (
          <svg viewBox="0 0 16 16" aria-hidden className="fx-arrow" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
            <path d="M2 8h11M9 4l4 4-4 4" />
          </svg>
        )}
      </span>
    </>
  )
  const cls = `fx-btn fx-${variant} ${className}`
  return to
    ? <Link ref={root} to={to} className={cls}>{inner}</Link>
    : <a ref={root} href={href} className={cls}>{inner}</a>
}
