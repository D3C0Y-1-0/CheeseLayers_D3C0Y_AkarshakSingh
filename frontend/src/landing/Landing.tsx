import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { openPortal } from './portal'
import Hero from './Hero'
import { Flow } from './Flow'
import { useSmoothScroll } from './useSmoothScroll'
import { Nav } from './Nav'
import { BlueprintFooter } from './BlueprintFooter'
import { Preview } from './Preview'
import { Exhibits } from './Exhibits'
import { ScoreLab, Sources } from './Sections'

export default function Landing() {
  useSmoothScroll()
  const navigate = useNavigate()

  // Every link into the dashboard goes through the light transition, from wherever it was clicked.
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
      const link = (e.target as Element).closest?.('a[href^="/app"]')
      if (!link) return
      e.preventDefault()
      e.stopPropagation()
      const box = link.getBoundingClientRect()
      const to = link.getAttribute('href')!
      openPortal(
        () => navigate(to, { state: to === '/app' ? { greet: true } : null }),
        e.clientX || box.left + box.width / 2,
        e.clientY || box.top + box.height / 2,
      )
    }
    document.addEventListener('click', onClick, true)
    return () => document.removeEventListener('click', onClick, true)
  }, [navigate])

  return (
    <>
      <a href="#how" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:bg-blue-fill focus:px-3 focus:py-1 focus:text-white">
        Skip the intro
      </a>
      <Nav />
      <main>
        <Hero />
        {/* Everything after the colour change sits on the white page. */}
        <div className="page-light">
          <Flow />
          <Preview />
          <Exhibits />
          <ScoreLab />
          <Sources />
          <BlueprintFooter />
        </div>
      </main>
    </>
  )
}
