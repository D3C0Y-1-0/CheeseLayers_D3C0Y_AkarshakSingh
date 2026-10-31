// WebGL scene for the opening scroll: a ring of glossy tiles orbits above a tilted, gently waving grid
// sheet, against a sky with one band of blue. Scrolling moves the camera between two framed "shots":
// RAMP (side-on ring beside the hero headline), HALO (face-on ring around the second headline), then
// PLAN and FIELD, where the tiles drop out of the ring and land flat on the grid behind the cards.
// Three.js ships in the bundle, so this runs with no network.
import * as THREE from 'three'
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js'
import { RoundedBoxGeometry } from 'three/examples/jsm/geometries/RoundedBoxGeometry.js'

// Each tile names something the system does. The label shows on hover. Paths use a 24-unit grid.
export const TILES = [
  { label: 'Mitigation', icon: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z M9 12l2 2 4-4' },
  { label: 'Early warning', icon: 'M12 3a9 9 0 1 0 9 9 M12 7.5a4.5 4.5 0 1 0 4.5 4.5 M12 12l6.5-6.5' },
  { label: 'Vulnerabilities', icon: 'M9 9a3 3 0 0 1 6 0v6a3 3 0 0 1-6 0z M9 11H5 M15 11h4 M9 15H5 M15 15h4 M10 6L8 4 M14 6l2-2' },
  { label: 'Correlation', icon: 'M12 7.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z M5 21.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z M19 21.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z M10.8 7.2L6.2 16.8 M13.2 7.2l4.6 9.6 M7.5 19h9' },
  { label: 'Exposure', icon: 'M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3' },
  { label: 'Alerts', icon: 'M12 4l9 16H3z M12 10v4 M12 17v.5' },
  { label: 'Assets', icon: 'M4 4h16v6H4z M4 14h16v6H4z M8 7h.01 M8 17h.01' },
  { label: 'Threat feeds', icon: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18' },
  { label: 'Log analysis', icon: 'M4 6l6 6-6 6 M12 18h8' },
  { label: 'Indicators', icon: 'M8 11a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M11 12l8-8 M16 7l3 3' },
  { label: 'Campaigns', icon: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z' },
  { label: 'Risk score', icon: 'M4 20V10 M10 20V4 M16 20v-7 M21 20H3' },
]

// A camera shot. Angles are in degrees. Every value blends from one shot to the next.
const RAMP = {
  tgtX: 2.4, tgtY: 1.2, tgtZ: -3, azim: 14, elev: 5, dist: 13, roll: 0, fov: 40, pan: 0.34, panY: 0.3,
  sky: -0.05, gX: 2, gY: -2, gZ: -9, pitch: 52, yaw: -16, spin: 0, wave: 0.8, flow: 3, grid: 1, dust: 0.3,
  ring: 5.2, ringY: 0.9, ringTilt: 6, ringDepth: 1, ringScale: 1.6, ringFace: 0, ringFront: 1, ringPace: 0.14, settle: 0, light: 0, drift: 0, gather: 0,
}
type Shot = typeof RAMP
const HALO: Shot = {
  tgtX: 0, tgtY: 1.6, tgtZ: 0, azim: 6, elev: 4, dist: 11, roll: -2, fov: 42, pan: 0, panY: 0,
  sky: -0.6, gX: 0, gY: 1.6, gZ: -7, pitch: 90, yaw: 0, spin: 18, wave: 1.1, flow: 2, grid: 0, dust: 1,
  ring: 5.4, ringY: 0, ringTilt: 84, ringDepth: 0.62, ringScale: 1, ringFace: 1, ringFront: 0, ringPace: 0.07, settle: 0, light: 0, drift: 0, gather: 0,
}
// Phones keep the same story with the ring pulled clear of the text.
const RAMP_PHONE: Shot = { ...RAMP, sky: -0.7, pan: 0, panY: 0.66, ring: 6.6, ringY: 1.1, ringScale: 2.5 }
const HALO_PHONE: Shot = { ...HALO, panY: 0.55, roll: 0, ring: 3, ringTilt: 40, ringY: 0.4, ringScale: 0.72 }

const LANDED = {
  roll: 0, fov: 40, pan: 0, panY: 0, pitch: 0, yaw: 0, spin: 0, flow: 0, grid: 1,
  ring: 3.4, ringY: 0, ringTilt: 22, ringDepth: 0.62, ringScale: 1, ringFace: 0, ringFront: 0, ringPace: 0.07, settle: 1, light: 0, drift: 0, gather: 0,
}
const PLAN: Shot = { ...LANDED, tgtX: 0, tgtY: -2, tgtZ: -2, azim: 12, elev: 58, dist: 14, sky: -2.2, gX: 0, gY: -2, gZ: -2, wave: 0.4, dust: 0.3 }
const FIELD: Shot = { ...LANDED, tgtX: 0, tgtY: -1.5, tgtZ: -3, azim: -14, elev: 44, dist: 13, sky: -4.4, gX: 0, gY: -2, gZ: -3, wave: 0.35, dust: 0.4 }

// The whole opening, in screens of scrolling. Hero.tsx times its text from these same numbers, and the
// section's height is PIN_END + 1 screens. Change them together to lengthen or shorten the sequence.
export const HOLD_END = 1.05 // hero holds until here
export const HALO_AT = 3 // ring is face-on
export const DROP_START = 4.6 // statement finished, tiles start falling
export const PLAN_AT = 5.6 // tiles have landed
export const FIELD_AT = 6.6 // camera settled behind the cards
export const CARDS_OUT = 7 // cards leave, the colour change starts
export const LIGHT_AT = 8.3 // sky is white, tiles have lifted to the edges
export const PROOF_OUT = 9 // warning card leaves
export const GATHER_START = 9.55 // tiles start flying into the diagram's hub (the section slides in here)
export const GATHER_END = 10.3 // tiles have landed in the hub
export const PIN_END = 10.5 // the diagram section sits exactly over the finished stage

// The colour change: dark floor, then the same floor lit, then white with the tiles lifted upright.
const LIT: Shot = { ...FIELD, azim: 4, elev: 30, dist: 13.5, light: 0.6, sky: -2.4, wave: 0.45, dust: 0.25 }
const WHITE: Shot = { ...FIELD, tgtX: 0, tgtY: -0.5, tgtZ: -3, azim: -6, elev: 9, dist: 14, gY: -3.1, light: 1, sky: -1.6, wave: 0.5, dust: 0.15, drift: 1 }

const GATHERED: Shot = { ...WHITE, gather: 1, grid: 0, dust: 0 }

const STOPS = (phone: boolean): [number, Shot][] => {
  const ramp = phone ? RAMP_PHONE : RAMP
  const halo = phone ? HALO_PHONE : HALO
  return [[HOLD_END, ramp], [HALO_AT, halo], [DROP_START, halo], [PLAN_AT, PLAN], [FIELD_AT, FIELD], [CARDS_OUT, FIELD], [CARDS_OUT + 0.5, LIT], [LIGHT_AT, WHITE], [GATHER_START, WHITE], [GATHER_END, GATHERED]]
}
const STOPS_WIDE = STOPS(false)
const STOPS_PHONE = STOPS(true)

// Where each tile lands, in grid cells on the sheet.
const LANDING = [[-4, -3], [-1, -4], [2, -3], [4, -1], [-3, 0], [0, -1], [3, 2], [-5, 2], [1, 2], [-2, 4], [4, 4], [-1, 1]]
const LAND_LIFT = 0.15

const eased = (t: number) => t * 0.7 + t * t * (3 - 2 * t) * 0.3

const SHEET = 36
const CELLS = 24
const CELL = SHEET / CELLS
const DEG = Math.PI / 180

const clamp = (v: number, a = 0, b = 1) => Math.min(b, Math.max(a, v))
const smooth = (a: number, b: number, v: number) => {
  const t = clamp((v - a) / (b - a))
  return t * t * (3 - 2 * t)
}
// Frame-rate independent easing towards a target: `rate` is how quickly it closes the gap.
const damp = (x: number, y: number, rate: number, dt: number) => x + (y - x) * (1 - Math.exp(-rate * dt))
const wrapAngle = (a: number) => a - Math.PI * 2 * Math.round(a / (Math.PI * 2))

function faceTexture() {
  const cv = document.createElement('canvas')
  cv.width = cv.height = 256
  const g = cv.getContext('2d')!
  const fill = g.createLinearGradient(0, 256, 256, 0)
  fill.addColorStop(0, '#1a4fe0')
  fill.addColorStop(0.5, '#3d8bff')
  fill.addColorStop(0.85, '#bcd7ff')
  fill.addColorStop(1, '#ffffff')
  g.fillStyle = fill
  g.fillRect(0, 0, 256, 256)
  const tex = new THREE.CanvasTexture(cv)
  tex.colorSpace = THREE.SRGBColorSpace
  return tex
}

function iconTexture(path: string) {
  const cv = document.createElement('canvas')
  cv.width = cv.height = 256
  const g = cv.getContext('2d')!
  g.scale(256 / 24, 256 / 24)
  g.strokeStyle = '#fff'
  g.lineWidth = 1.75
  g.lineCap = 'round'
  g.lineJoin = 'round'
  g.stroke(new Path2D(path))
  const tex = new THREE.CanvasTexture(cv)
  tex.colorSpace = THREE.SRGBColorSpace
  tex.anisotropy = 4
  return tex
}

const SKY_VERT = /* glsl */ `
  varying vec3 vDir;
  void main() {
    vDir = position;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }`
const SKY_FRAG = /* glsl */ `
  uniform float time;
  uniform float phase;
  uniform float light;
  uniform vec3 night;
  uniform vec3 blue;
  uniform vec3 edge;
  uniform vec3 nightLight;
  uniform vec3 blueLight;
  uniform vec3 edgeLight;
  varying vec3 vDir;

  float hash(vec3 p) {
    return fract(sin(dot(p, vec3(127.1, 311.7, 74.7))) * 43758.5453);
  }
  float valueNoise(vec3 p) {
    vec3 i = floor(p);
    vec3 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    float near = mix(
      mix(hash(i), hash(i + vec3(1, 0, 0)), f.x),
      mix(hash(i + vec3(0, 1, 0)), hash(i + vec3(1, 1, 0)), f.x), f.y);
    float far = mix(
      mix(hash(i + vec3(0, 0, 1)), hash(i + vec3(1, 0, 1)), f.x),
      mix(hash(i + vec3(0, 1, 1)), hash(i + vec3(1, 1, 1)), f.x), f.y);
    return mix(near, far, f.z);
  }
  void main() {
    // A slow noise twists one wide sine band, so the blue edge curves and drifts instead of sitting still.
    vec3 p = vDir * 0.03;
    float twist = valueNoise(p + time);
    float across = cos(twist) * p.x - sin(twist) * p.y;
    float band = 0.5 + 0.5 * sin(across * 1.25 + phase);
    // Between dark and white the base colour swings through blue, so it never passes through flat grey.
    float l = smoothstep(0.15, 0.85, light);
    float via = sin(3.14159 * l) * 0.5;
    vec3 base = mix(mix(night, nightLight, l), blue, via);
    vec3 c = mix(base, mix(blue, blueLight, l), smoothstep(0.42, 0.78, band));
    c = mix(c, mix(edge, edgeLight, l), smoothstep(0.8, 0.99, band));
    gl_FragColor = vec4(c, 1.0);
    #include <colorspace_fragment>
  }`

const SHEET_VERT = /* glsl */ `
  uniform float time;
  uniform float wave;
  varying vec2 vUv;
  void main() {
    vUv = uv;
    vec3 p = position;
    p.y = sin(time * 0.9 + p.x * 0.22 + p.z * 0.18) * 0.45 * wave;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
  }`
const SHEET_FRAG = /* glsl */ `
  uniform float flow;
  uniform float opacity;
  uniform float cells;
  uniform float light;
  uniform vec3 lineColor;
  uniform vec3 focusColor;
  uniform vec2 focus;
  uniform float focusAmount;
  varying vec2 vUv;

  void main() {
    vec2 g = (vUv - 0.5) * cells;
    g.y += flow;
    vec2 px = fwidth(g);

    // Thin lines on every cell edge, kept to about one pixel however far away they recede.
    vec2 toLine = abs(g - round(g));
    vec2 onLine = 1.0 - smoothstep(px * 0.5, px * 1.2, toLine);
    float line = max(onLine.x, onLine.y);

    // A plus sign on every second crossing.
    vec2 q = abs(g - round(g / 2.0) * 2.0);
    float bar = min(max(q.x - 0.2, q.y - 0.02), max(q.x - 0.02, q.y - 0.2));
    float plus = 1.0 - smoothstep(0.0, max(px.x, 0.01) * 1.2, bar);

    float alpha = max(line * mix(0.4, 0.14, light), plus * mix(0.9, 0.55, light));
    vec3 color = mix(lineColor, vec3(0.0), light);

    // Lines near the pointer pick up the blue.
    float near = (1.0 - smoothstep(0.7, 3.0, length(g - focus))) * focusAmount;
    color = mix(color, focusColor, near);
    alpha = max(alpha, line * near * 0.7);

    // The sheet dissolves into the sky well before its edge.
    float r = length((vUv - 0.5) * 2.0);
    alpha *= 1.0 - smoothstep(0.3, 1.0, r);

    gl_FragColor = vec4(color, alpha * opacity);
    #include <colorspace_fragment>
  }`

const DUST_VERT = /* glsl */ `
  attribute float seed;
  uniform float time;
  uniform float proj;
  uniform vec3 centre;
  uniform vec3 box;
  varying float vAlpha;
  void main() {
    vec3 p = position;
    p.y += time * (0.04 + seed * 0.06);
    p.x += sin(time * 0.1 + seed * 30.0) * 0.5;
    // Wraps inside a box that follows the camera, so the field never runs out.
    vec3 d = mod(p - centre + box, 2.0 * box) - box;
    vec4 mv = modelViewMatrix * vec4(centre + d, 1.0);
    float depth = -mv.z;
    vec3 e = abs(d) / box;
    float walls = 1.0 - smoothstep(0.6, 1.0, max(e.x, max(e.y, e.z)));
    vAlpha = walls * smoothstep(1.0, 3.5, depth) * (0.6 + 0.4 * sin(time * 0.8 + seed * 40.0));
    gl_PointSize = min(0.07 * (0.5 + seed) * proj / max(depth, 0.1), 90.0);
    gl_Position = projectionMatrix * mv;
  }`
const DUST_FRAG = /* glsl */ `
  uniform vec3 color;
  uniform vec3 colorLight;
  uniform float light;
  uniform float opacity;
  varying float vAlpha;
  void main() {
    float a = (1.0 - smoothstep(0.12, 0.5, length(gl_PointCoord - 0.5))) * vAlpha * opacity;
    if (a < 0.004) discard;
    gl_FragColor = vec4(mix(color, colorLight, light), a);
    #include <colorspace_fragment>
  }`

export function createOrbit(canvas: HTMLCanvasElement, opts: {
  reduced: boolean
  chip: HTMLElement
  chipLabel: HTMLElement
  // Where the diagram's hub currently is on screen. Tiles fly into it.
  hubPoint: () => { x: number; y: number } | null
}) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' })
  renderer.toneMapping = THREE.NoToneMapping
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75))

  const scene = new THREE.Scene()
  const camera = new THREE.PerspectiveCamera(40, 2, 0.1, 160)

  // Lighting: a studio environment for the clear-coat reflections, plus a key and a cool fill.
  const pmrem = new THREE.PMREMGenerator(renderer)
  const env = pmrem.fromScene(new RoomEnvironment(), 0.04)
  scene.environment = env.texture
  scene.add(new THREE.AmbientLight(0xffffff, 0.55))
  const key = new THREE.DirectionalLight(0xffffff, 1.05)
  key.position.set(4, 7, 6)
  const fill = new THREE.DirectionalLight(0x9fc2ff, 0.35)
  fill.position.set(-6, 2, -2)
  scene.add(key, fill)

  // Sky
  const skyMat = new THREE.ShaderMaterial({
    side: THREE.BackSide,
    depthWrite: false,
    toneMapped: false,
    uniforms: {
      time: { value: 0 },
      phase: { value: 0 },
      night: { value: new THREE.Color('#040917') },
      blue: { value: new THREE.Color('#2f74ff') },
      edge: { value: new THREE.Color('#dce6f8') },
      light: { value: 0 },
      nightLight: { value: new THREE.Color('#e7ecf5') },
      blueLight: { value: new THREE.Color('#d5e1f6') },
      edgeLight: { value: new THREE.Color('#f7f9fc') },
    },
    vertexShader: SKY_VERT,
    fragmentShader: SKY_FRAG,
  })
  const sky = new THREE.Mesh(new THREE.SphereGeometry(64, 64, 32), skyMat)
  sky.renderOrder = -10
  sky.frustumCulled = false
  scene.add(sky)

  // Grid sheet
  const sheetGeo = new THREE.PlaneGeometry(SHEET, SHEET, 144, 144).rotateX(-Math.PI / 2)
  const sheetMat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    side: THREE.DoubleSide,
    toneMapped: false,
    uniforms: {
      time: { value: 0 },
      wave: { value: 0 },
      flow: { value: 0 },
      opacity: { value: 1 },
      cells: { value: CELLS },
      light: { value: 0 },
      lineColor: { value: new THREE.Color('#e6eeff') },
      focusColor: { value: new THREE.Color('#3d8bff') },
      focus: { value: new THREE.Vector2() },
      focusAmount: { value: 0 },
    },
    vertexShader: SHEET_VERT,
    fragmentShader: SHEET_FRAG,
  })
  const sheet = new THREE.Mesh(sheetGeo, sheetMat)
  sheet.frustumCulled = false
  scene.add(sheet)

  // Dust
  const DUST = 1800
  const box = new THREE.Vector3(26, 15, 26)
  const dustPos = new Float32Array(DUST * 3)
  const dustSeed = new Float32Array(DUST)
  for (let i = 0; i < DUST; i++) {
    dustPos[i * 3] = (Math.random() * 2 - 1) * box.x
    dustPos[i * 3 + 1] = (Math.random() * 2 - 1) * box.y
    dustPos[i * 3 + 2] = (Math.random() * 2 - 1) * box.z
    dustSeed[i] = Math.random()
  }
  const dustGeo = new THREE.BufferGeometry()
  dustGeo.setAttribute('position', new THREE.BufferAttribute(dustPos, 3))
  dustGeo.setAttribute('seed', new THREE.BufferAttribute(dustSeed, 1))
  const dustMat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    toneMapped: false,
    uniforms: {
      time: { value: 0 },
      proj: { value: 1 },
      centre: { value: new THREE.Vector3() },
      box: { value: box },
      color: { value: new THREE.Color('#cfe0ff') },
      colorLight: { value: new THREE.Color('#3d8bff') },
      light: { value: 0 },
      opacity: { value: 0 },
    },
    vertexShader: DUST_VERT,
    fragmentShader: DUST_FRAG,
  })
  const dust = new THREE.Points(dustGeo, dustMat)
  dust.frustumCulled = false
  scene.add(dust)

  // Tiles
  const tileGeo = new RoundedBoxGeometry(1, 1, 0.24, 4, 0.06)
  const iconGeo = new THREE.PlaneGeometry(0.58, 0.58)
  const sideMat = new THREE.MeshPhysicalMaterial({
    color: '#2f74f0', roughness: 0.3, clearcoat: 0.8, envMap: env.texture, envMapIntensity: 0.9,
  })
  const faceMat = new THREE.MeshPhysicalMaterial({
    map: faceTexture(), roughness: 0.28, clearcoat: 0.8, clearcoatRoughness: 0.06, envMap: env.texture, envMapIntensity: 0.8,
  })
  const tileMats = [sideMat, sideMat, sideMat, sideMat, faceMat, sideMat]
  const tiles = TILES.map((t, tiles_i) => {
    const group = new THREE.Group()
    const body = new THREE.Mesh(tileGeo, tileMats)
    const icon = new THREE.Mesh(iconGeo, new THREE.MeshBasicMaterial({ map: iconTexture(t.icon), transparent: true, toneMapped: false }))
    icon.position.z = 0.122
    group.add(body, icon)
    scene.add(group)
    return {
      group, body, hover: 0, size: 0, landed: 0,
      // Tiles leave one after another on their own small arc, so the drop looks like a shuffle.
      delay: 0.5 * (0.75 * (tiles_i / (TILES.length - 1)) + 0.25 * Math.random()),
      arc: 0.25 + Math.random() * 0.45,
    }
  })

  // Live state
  const shot: Shot = { ...RAMP }
  let first = true
  let scrollPx = 0
  let lastScreens = 0
  let smoothScreens = 0
  let velocity = 0
  let time = 0
  let last = 0
  let raf = 0
  let running = false
  let W = 1
  let H = 1
  let ringAngle = 0
  let pace = RAMP.ringPace
  let lastRevolve: number | null = null
  let travel = 0
  let hovered = -1
  let chipShow = 0
  let chipFor = -1

  const pointer = { x: 0, y: 0, moved: false, overUI: false, energy: 0, smoothX: 0, smoothY: 0 }
  const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches
  const focus = { x: 0, y: 0, amount: 0 }

  function onPointer(e: PointerEvent) {
    const rect = canvas.getBoundingClientRect()
    pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1
    pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1
    pointer.moved = true
    pointer.energy = 1
    // Cards and buttons sit above the canvas, so tiles behind them must not react.
    pointer.overUI = e.target instanceof Element && e.target.closest('.feature-card, .proof-card, a, button, header') !== null
  }
  window.addEventListener('pointermove', onPointer, { passive: true })

  const ray = new THREE.Raycaster()
  const ndc = new THREE.Vector2()
  const qYaw = new THREE.Quaternion()
  const qPitch = new THREE.Quaternion()
  const qSpin = new THREE.Quaternion()
  const qTilt = new THREE.Quaternion()
  const qOut = new THREE.Quaternion()
  const qFace = new THREE.Quaternion()
  const X = new THREE.Vector3(1, 0, 0)
  const Y = new THREE.Vector3(0, 1, 0)
  const centre = new THREE.Vector3()
  const pos = new THREE.Vector3()
  const toCam = new THREE.Vector3()
  const facePoint = new THREE.Vector3()
  const hit = new THREE.Vector3()
  const normal = new THREE.Vector3()
  const plane = new THREE.Plane()
  const proj = new THREE.Vector3()
  const dummy = new THREE.Object3D()
  const landAt = new THREE.Vector3()
  const driftAt = new THREE.Vector3()
  const gatherAt = new THREE.Vector3()
  const qLand = new THREE.Quaternion()
  const qFlat = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1, 0, 0), -Math.PI / 2)
  const qArc = new THREE.Quaternion()

  function resize() {
    const rect = canvas.getBoundingClientRect()
    if (!rect.width || !rect.height) return
    W = rect.width
    H = rect.height
    renderer.setSize(W, H, false)
    camera.aspect = W / H
    camera.updateProjectionMatrix()
    if (opts.reduced) frame(0)
  }

  function frame(dt: number) {
    const snap = first || opts.reduced

    // 1. Where the scroll position says the shot should be. Each stop blends from the previous one.
    const phone = H > W * 1.15
    const stops = phone ? STOPS_PHONE : STOPS_WIDE
    const screens = scrollPx / H
    let fromShot = stops[0][1]
    let toShot = stops[0][1]
    let blend = 0
    for (let i = 1; i < stops.length; i++) {
      const [at, stop] = stops[i]
      const startAt = stops[i - 1][0]
      if (screens >= startAt) {
        fromShot = stops[i - 1][1]
        toShot = stop
        blend = eased(clamp((screens - startAt) / (at - startAt)))
      }
    }
    const keys = Object.keys(shot) as (keyof Shot)[]
    for (const k of keys) {
      const target = fromShot[k] + (toShot[k] - fromShot[k]) * blend
      shot[k] = snap ? target : damp(shot[k], target, 2.3, dt)
    }

    // 2. A lightly smoothed scroll position drives everything continuous, so nothing ever steps.
    smoothScreens = snap ? screens : damp(smoothScreens, screens, 14, dt)
    const instant = dt > 0 ? (smoothScreens - lastScreens) / dt : 0
    lastScreens = smoothScreens
    velocity = damp(velocity, clamp(instant, -4, 4), 6, dt)
    const toHalo = clamp((smoothScreens - HOLD_END) / (HALO_AT - HOLD_END))

    // 3. Camera. Scroll position sways it, which is what makes the tilted grid rock as you move down
    // the page. The pointer adds a little parallax, and a slow idle drift keeps it alive at rest.
    pointer.smoothX = damp(pointer.smoothX, clamp(pointer.x, -1, 1), 2, dt)
    pointer.smoothY = damp(pointer.smoothY, clamp(pointer.y, -1, 1), 2, dt)
    // This sequence is about half the usual scroll length, so the sway runs at double speed to keep its feel.
    const sway = smoothScreens * 1.35
    const held = Math.min(Math.min(sway, HOLD_END * 1.35) * (1 - eased(toHalo)), 7)
    const swayA = phone ? 0.55 : 1
    const swayB = phone ? 1.6 : 1
    const swayAzim = (held * 3.2 + Math.sin(sway * 1.05) * 7 + Math.sin(sway * 0.43 + 1) * 5) * swayA
    const swayElev = (held * 0.5 + Math.sin(sway * 0.74 + 2) * 3) * swayB
    const dolly = (1 - held * 0.022) * (1 + Math.sin(sway * 0.84 + 0.5) * 0.06)
    const rise = Math.sin(sway * 0.66) * 0.35 * swayB

    const tall = Math.max(0, (1.2 * H) / Math.max(W, 1) - 1)
    const azim = (shot.azim + swayAzim + pointer.smoothX * 2.5 + Math.sin(time * 0.17) * 1.4) * DEG
    const elev = Math.min(89, shot.elev + swayElev + pointer.smoothY * 1.5 + Math.sin(time * 0.23) * 0.8) * DEG
    const dist = shot.dist * dolly * (1 + tall * 0.12) + Math.cos(time * 0.13) * 0.2
    centre.set(shot.tgtX, shot.tgtY + rise, shot.tgtZ)
    camera.position
      .set(Math.cos(elev) * Math.sin(azim), Math.sin(elev), Math.cos(elev) * Math.cos(azim))
      .multiplyScalar(dist)
      .add(centre)
    camera.lookAt(centre)
    camera.rotateZ(shot.roll * DEG)

    const fov = (2 * Math.atan(Math.tan(((shot.fov + Math.min(Math.abs(velocity), 3) * 0.8) * DEG) / 2) * (1 + tall * 0.35))) / DEG
    camera.fov = fov
    // Shifts the whole picture sideways and up without turning the camera, so the headline gets its room.
    camera.filmOffset = -(shot.pan * Math.max(0, 1 - tall)) * Math.tan((fov * DEG) / 2) * camera.aspect * camera.getFilmWidth()
    const offsetY = (shot.panY * H) / 2
    if (Math.abs(offsetY) > 0.5) camera.setViewOffset(W, H, 0, offsetY, W, H)
    else camera.clearViewOffset()
    camera.updateProjectionMatrix()
    camera.updateMatrixWorld()

    // 4. Sky, sheet and dust.
    sky.position.copy(camera.position)
    skyMat.uniforms.time.value = time * 0.04
    skyMat.uniforms.phase.value = shot.sky
    skyMat.uniforms.light.value = shot.light

    sheet.position.set(shot.gX, shot.gY, shot.gZ)
    qYaw.setFromAxisAngle(Y, shot.yaw * DEG)
    qPitch.setFromAxisAngle(X, shot.pitch * DEG)
    qSpin.setFromAxisAngle(Y, shot.spin * DEG)
    sheet.quaternion.copy(qYaw).multiply(qPitch).multiply(qSpin)
    sheet.updateMatrixWorld()
    // The grid scrolls past while the ring is up. Once tiles land it eases onto a whole plus-sign step,
    // so they sit square in the grid.
    travel += (shot.flow * 0.12 + velocity * 1.4 * (1 - shot.settle)) * dt
    if (shot.flow < 0.5 && Math.abs(velocity) < 0.05) travel = damp(travel, Math.round(travel / 3) * 3, 3, dt)
    travel = ((travel % 18) + 18) % 18
    const su = sheetMat.uniforms
    su.time.value = time
    su.wave.value = shot.wave
    su.light.value = shot.light
    su.flow.value = travel / CELL
    su.opacity.value = shot.grid
    sheet.visible = shot.grid > 0.002

    dustMat.uniforms.time.value = time
    dustMat.uniforms.proj.value = (H * renderer.getPixelRatio()) / (2 * Math.tan((fov * DEG) / 2))
    dustMat.uniforms.centre.value.copy(camera.position)
    dustMat.uniforms.opacity.value = shot.dust * (1 - shot.light * 0.45)
    dustMat.uniforms.light.value = shot.light

    // 5. Pointer on the sheet: the blue patch under the cursor. It fades once the pointer rests.
    pointer.energy *= Math.exp(-dt * 0.8)
    ndc.set(pointer.x, pointer.y)
    ray.setFromCamera(ndc, camera)
    plane.setFromNormalAndCoplanarPoint(normal.set(0, 1, 0).applyQuaternion(sheet.quaternion), sheet.position)
    const onSheet = ray.ray.intersectPlane(plane, hit) !== null
    if (onSheet) {
      sheet.worldToLocal(hit)
      const fx = Math.floor(hit.x / CELL) + 0.5
      const fy = Math.floor(-hit.z / CELL + travel / CELL) + 0.5
      const jump = Math.abs(fx - focus.x) > 3 || Math.abs(fy - focus.y) > 3
      focus.x = jump ? fx : damp(focus.x, fx, 16, dt)
      focus.y = jump ? fy : damp(focus.y, fy, 16, dt)
    }
    const focusOn = onSheet && fine && pointer.moved && pointer.energy > 0.05 && hovered < 0
    focus.amount = damp(focus.amount, focusOn ? shot.grid : 0, 6, dt)
    su.focus.value.set(focus.x, focus.y)
    su.focusAmount.value = focus.amount

    // 6. The ring. It always turns, and the move between shots adds one extra revolution.
    // Half a turn on the way to the face-on ring: a full one looked rushed.
    const revolve = Math.PI * toHalo
    const extra = dt > 0 && lastRevolve !== null ? wrapAngle(revolve - lastRevolve) / dt : 0
    lastRevolve = revolve
    pace = damp(pace, shot.ringPace + extra, 1.8, dt)
    ringAngle = (ringAngle + pace * dt) % (Math.PI * 2)

    centre.set(shot.tgtX, shot.tgtY + shot.ringY, shot.tgtZ)
    qTilt.setFromAxisAngle(X, shot.ringTilt * DEG)
    facePoint.copy(camera.position)
    facePoint.y -= 5

    const hub = shot.gather > 0.001 ? opts.hubPoint() : null
    if (hub) {
      proj.set((hub.x / W) * 2 - 1, -(hub.y / H) * 2 + 1, 0.5).unproject(camera)
      gatherAt.copy(proj).sub(camera.position).normalize().multiplyScalar(12).add(camera.position)
    }

    const wasHovered = hovered
    tiles.forEach((tile, i) => {
      const a = (i / tiles.length) * Math.PI * 2 + ringAngle
      pos
        .set(Math.cos(a) * shot.ring, Math.sin(time * 0.7 + i * 1.3) * 0.2, Math.sin(a) * shot.ring * shot.ringDepth)
        .applyQuaternion(qTilt)
        .add(centre)

      // Side-on, a tile looks away from the ring's centre. Face-on, it looks towards the viewer.
      dummy.position.copy(pos)
      dummy.lookAt(facePoint)
      qFace.copy(dummy.quaternion)
      dummy.lookAt(centre)
      dummy.rotateY(Math.PI)
      qOut.copy(dummy.quaternion).slerp(qFace, shot.ringFace)

      // Tiles on the far side of the ring shrink down to the small floating boxes.
      const behind = -Math.sin(a)
      const midMove = smooth(0, 0.08, shot.ringFace) * smooth(0, 0.08, 1 - shot.ringFace)
      const shrink = shot.ringFront * smooth(-0.35, 0.1, behind)
      const target = shot.ringScale * (1 - midMove * smooth(0.9, 1, behind)) * (1 - shrink * 0.92)

      // Falling: each tile leaves the ring on its own delay, arcs up slightly, and lands flat on the grid.
      const drop = clamp((screens - DROP_START) / (PLAN_AT - DROP_START))
      const leave = clamp((drop - tile.delay) / 0.5)
      tile.landed = snap ? leave : damp(tile.landed, leave, 3.5, dt)
      const [cellX, cellZ] = LANDING[i % LANDING.length]
      const landX = (cellX + 0.5) * CELL
      const landZ = (cellZ + 0.5) * CELL
      const swell = Math.sin(time * 0.9 + landX * 0.22 + landZ * 0.18) * 0.45 * shot.wave
      landAt.set(landX, swell + LAND_LIFT, landZ).applyMatrix4(sheet.matrixWorld)
      qLand.copy(sheet.quaternion).multiply(qFlat)
      const arc = Math.sin(Math.PI * leave)
      pos.lerp(landAt, tile.landed)
      pos.y += arc * tile.arc
      qOut.slerp(qLand, tile.landed)
      qOut.multiply(qArc.setFromAxisAngle(X, arc * (i % 2 === 0 ? 0.25 : -0.25)))

      // Lifting: on the white stage each tile leaves the floor and floats upright near the screen edge,
      // framing the headline and card. Positions are in view space so they hold on any screen shape.
      if (shot.drift > 0.001) {
        const ahead = 12
        const halfH = Math.tan((fov * DEG) / 2) * ahead
        const halfW = halfH * camera.aspect
        const orbitA = (i / tiles.length) * Math.PI * 2 + 0.26 + time * 0.018
        driftAt
          // The square root pushes tiles out of the middle column. The top limit keeps them clear of the nav.
          .set(
            Math.sign(Math.cos(orbitA)) * Math.sqrt(Math.abs(Math.cos(orbitA))) * halfW * 0.86,
            // Phones have no side margin beside the headline, so every tile stays in the lower half there.
            (phone ? -Math.abs(Math.sin(orbitA)) * halfH * 0.97 : Math.sin(orbitA) * halfH * (Math.sin(orbitA) > 0 ? 0.66 : 0.95)) + Math.sin(time * 0.6 + i * 1.7) * 0.1,
            -ahead + Math.sin(i * 2.3) * 1.2,
          )
          .applyMatrix4(camera.matrixWorld)
        pos.lerp(driftAt, shot.drift)
        dummy.position.copy(pos)
        dummy.lookAt(camera.position)
        dummy.rotateX(-0.16 + Math.sin(i * 1.9) * 0.1)
        dummy.rotateY(Math.sin(i * 2.7) * 0.38)
        dummy.rotateZ(Math.sin(i * 3.1) * 0.12)
        qOut.slerp(dummy.quaternion, shot.drift)
      }

      // Gathering: tiles leave one after another and pour into the hub of the diagram below.
      const gd = tile.delay * 0.6
      const gathered = hub ? clamp((shot.gather - gd) / (1 - gd)) : 0
      if (gathered > 0) {
        const g = gathered * gathered * (3 - 2 * gathered)
        pos.lerp(gatherAt, g)
      }

      const sized = target + (1 - target) * tile.landed
      tile.size = snap ? sized : damp(tile.size, sized, 3, dt)

      // Hover: the tile comes towards the camera and grows.
      tile.hover = damp(tile.hover, i === wasHovered ? 1 : 0, 8, dt)
      toCam.copy(camera.position).sub(pos).normalize()
      pos.addScaledVector(toCam, tile.hover * 0.6)
      tile.group.position.copy(pos)
      tile.group.quaternion.copy(qOut)
      tile.group.scale.setScalar(Math.max(tile.size * (1 + tile.hover * 0.14) * (1 - smooth(0.62, 1, gathered)), 0.001))
      tile.group.updateMatrixWorld()
    })
    first = false

    // 7. Which tile is under the pointer, and the label that follows it.
    hovered = -1
    if (pointer.moved && fine && !opts.reduced && !pointer.overUI) {
      let nearest = Infinity
      tiles.forEach((tile, i) => {
        if (tile.size < 0.4) return
        const found = ray.intersectObject(tile.body, false)[0]
        if (found && found.distance < nearest) {
          nearest = found.distance
          hovered = i
        }
      })
    }
    chipShow = damp(chipShow, hovered >= 0 ? 1 : 0, 10, dt)
    if (hovered >= 0) {
      if (hovered !== chipFor) {
        chipFor = hovered
        opts.chipLabel.textContent = TILES[hovered].label
      }
      proj.copy(tiles[hovered].group.position).project(camera)
      opts.chip.style.transform = `translate3d(${((proj.x + 1) / 2) * W + 26}px, ${((1 - proj.y) / 2) * H - 44}px, 0)`
    }
    opts.chip.style.opacity = chipShow.toFixed(3)

    renderer.render(scene, camera)
  }

  function loop(now: number) {
    if (!running) return
    const dt = Math.min(0.05, (now - last) / 1000 || 0)
    last = now
    time += dt
    frame(dt)
    raf = requestAnimationFrame(loop)
  }

  const ro = new ResizeObserver(resize)
  ro.observe(canvas)
  resize()
  frame(0)

  return {
    setScroll(px: number) {
      scrollPx = px
      if (opts.reduced) frame(0)
    },
    // Called by an IntersectionObserver: no GPU use once the hero has scrolled away.
    setActive(active: boolean) {
      if (opts.reduced || active === running) return
      running = active
      if (active) {
        last = performance.now()
        raf = requestAnimationFrame(loop)
      } else {
        cancelAnimationFrame(raf)
      }
    },
    destroy() {
      running = false
      cancelAnimationFrame(raf)
      ro.disconnect()
      window.removeEventListener('pointermove', onPointer)
      env.dispose()
      pmrem.dispose()
      renderer.dispose()
    },
  }
}
