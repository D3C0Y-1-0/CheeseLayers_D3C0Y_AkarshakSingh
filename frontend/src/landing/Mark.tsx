// The Vectra mark: a V cut from two angled strokes, with the right one lit.
export function Mark({ className = 'size-5' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className} fill="currentColor">
      <path d="M2 4h5.2L12 15.2 10 20z" opacity="0.55" />
      <path d="M22 4h-5.2L9.6 20h4.8z" />
    </svg>
  )
}
