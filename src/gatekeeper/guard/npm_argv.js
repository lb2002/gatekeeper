// Read an npm/npx command line the way the installed npm itself does, and resolve what it would install or run.
// Uses npm's own modules: @npmcli/config (options, shorthands, abbreviations, .npmrc files, npm_config_* env),
// cmd-list (command aliases and abbreviations), npm-package-arg (spec types) and pacote (version selection with
// the same registry, tag and `before` settings). Nothing is installed or executed; only registry metadata is read.
//
//   node npm_argv.js <npm root> <npm|npx> [args...]   ->  JSON on stdout
'use strict'

const path = require('path')
const [npmRoot, tool, ...userArgs] = process.argv.slice(2)
const req = (m) => require(path.join(npmRoot, 'node_modules', m))
const Config = req('@npmcli/config')
const { definitions, flatten, shorthands } = req('@npmcli/config/lib/definitions')
// loaded only when the command installs or runs something: most npm calls (run, test, ...) never need them
const lazy = (m) => { let mod; return () => (mod = mod || req(m)) }
const npaMod = lazy('npm-package-arg')
const pacoteMod = lazy('pacote')
const npa = (...a) => npaMod()(...a)
const { deref } = require(path.join(npmRoot, 'lib', 'utils', 'cmd-list.js'))

const INSTALL = new Set(['install', 'install-test', 'update'])
const EXEC = new Set(['exec'])
const INIT = new Set(['init'])
// commands that fetch (and, for git specs, build) packages without installing them: only remote specs matter here,
// because pacote runs `npm install` and the `prepare` script inside a git clone to pack it
const INSPECT = new Set(['pack', 'cache', 'diff', 'view', 'publish'])
const fs = require('fs')

// commands that never install the project's dependency tree; every other command gets the lockfile check
const READ_ONLY = new Set(['run-script', 'test', 'start', 'stop', 'restart', 'view', 'outdated', 'search', 'ls', 'config',
  'help', 'help-search', 'version', 'whoami', 'ping', 'root', 'prefix', 'docs', 'bugs', 'repo', 'explain', 'query',
  'fund', 'doctor', 'sbom', 'pkg', 'completion', 'login', 'logout', 'adduser', 'token', 'profile', 'owner', 'access',
  'team', 'org', 'star', 'unstar', 'stars', 'hook', 'dist-tag', 'deprecate', 'undeprecate', 'unpublish', 'cache',
  'diff', 'pack', 'publish', 'edit', 'explore', 'get', 'set', 'find-dupes'])
const PUBLIC = ['https://registry.npmjs.org/', 'https://registry.yarnpkg.com/']
const slash = (u) => String(u).replace(/\/?$/, '/')

// Registries a project's own .npmrc points somewhere other than the public registry. A cloned repository controls
// that file, so such a registry is not trusted unless the user says so (GK_TRUST_PROJECT_REGISTRY=1).
function projectRegistries (config) {
  const out = []
  for (const layer of ['project']) {
    const data = (config.data.get(layer) || {}).data || {}
    for (const [k, v] of Object.entries(data)) {
      if ((k === 'registry' || k.endsWith(':registry')) && !PUBLIC.includes(slash(v))) out.push(`${k}=${v}`)
    }
  }
  return out
}

// Lockfile entries npm would fetch from somewhere other than their registry. npm installs locked transitive
// dependencies from their `resolved` URL as written, and a cloned repository controls that file. A scoped
// registry only counts for packages of that scope; the public registry always counts (its packages are checked).
function offRegistryLockEntries (flat, prefix) {
  let lock = null
  for (const f of ['npm-shrinkwrap.json', 'package-lock.json']) {
    try { lock = JSON.parse(fs.readFileSync(path.join(prefix, f), 'utf8')); break } catch (e) {}
  }
  if (!lock) return []
  const entries = []
  for (const [p, e] of Object.entries(lock.packages || {})) if (p) entries.push([p, e])
  const walk = (deps, at) => {
    for (const [n, e] of Object.entries(deps || {})) {
      entries.push([at + n, e])
      walk(e && e.dependencies, at + n + '/node_modules/')
    }
  }
  walk(lock.dependencies, 'node_modules/') // lockfile v1, and the v2 copy of it: both are checked
  const out = []
  for (const [p, e] of entries) {
    if (!e || e.link || e.inBundle || !e.resolved) continue
    const r = String(e.resolved)
    if (r.startsWith('file:')) continue // the project's own files
    const name = p.split('node_modules/').pop()
    const scope = name.startsWith('@') ? name.split('/')[0] : null
    const own = scope && flat[`${scope}:registry`] ? flat[`${scope}:registry`] : flat.registry
    if (![slash(own), ...PUBLIC].some((reg) => r.startsWith(reg))) out.push(`${r} (package-lock: ${p})`)
  }
  return out
}

// what `npm install <bare name>` really resolves when the project already has it: arborist keeps the lockfile's
// version, or else the range saved in package.json (build-ideal-tree: "if it's just @'' ... reload what's there")
// what `npm install <bare name>` / `npm update <name>` really resolves when package.json already lists the
// package: arborist re-resolves the saved range (with the same --before), not the lockfile's version, for
// packages named on the command line. A name not in package.json is added at its latest version.
let projectPrefix = process.cwd()

function projectSpec (spec) {
  let r
  try { r = npa(spec) } catch (e) { return spec }
  if (!r.registry || (r.rawSpec !== '' && r.rawSpec !== '*')) return spec
  let pkg = {}
  try { pkg = JSON.parse(fs.readFileSync(path.join(projectPrefix, 'package.json'), 'utf8')) } catch (e) {}
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const range = (pkg[section] || {})[r.name]
    if (typeof range === 'string') return `${r.name}@${range}`
  }
  return spec
}

// npx -> `npm exec ...`, the same rewriting as npm's bin/npx-cli.js
function npxToExec (args) {
  const argv = ['exec', ...args]
  const removedSwitches = new Set(['always-spawn', 'ignore-existing', 'shell-auto-fallback'])
  const removedOpts = new Set(['npm', 'node-arg', 'n'])
  const removed = new Set([...removedSwitches, ...removedOpts])
  const npmSwitches = Object.entries(definitions)
    .filter(([, { type }]) => type === Boolean || (Array.isArray(type) && type.includes(Boolean)))
    .map(([key]) => key)
  const switches = new Set([...removedSwitches, ...npmSwitches, 'no-install', 'quiet', 'q', 'version', 'v', 'help', 'h'])
  const opts = new Set([...removedOpts, 'package', 'p', 'cache', 'userconfig', 'call', 'c', 'shell', 'npm', 'node-arg', 'n'])
  let i
  for (i = 1; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--') {
      break
    } else if (/^-/.test(arg)) {
      const [key, ...v] = arg.replace(/^-+/, '').split('=')
      switch (key) {
        case 'p': argv[i] = ['--package', ...v].join('='); break
        case 'shell': argv[i] = ['--script-shell', ...v].join('='); break
        case 'no-install': argv[i] = '--yes=false'; break
        default:
          if (shorthands[key] && !removed.has(key)) {
            const a = [...shorthands[key]]
            if (v.length) a.push(v.join('='))
            argv.splice(i, 1, ...a)
            i--
            continue
          }
      }
      if (removed.has(key)) {
        argv.splice(i, 1)
        i--
      }
      if (v.length === 0 && !switches.has(key) && (opts.has(key) || !/^-/.test(argv[i + 1]))) {
        if (removed.has(key)) argv.splice(i + 1, 1)
        else i++
      }
    } else {
      argv.splice(i, 0, '--')
      break
    }
  }
  return argv
}

// the package `npm init <initializer>` / `npm create <initializer>` runs (npm's lib/commands/init.js execCreate)
function createPackage (initer) {
  if (/^@[^/]+$/.test(initer)) {
    const [, scope, version] = initer.split('@')
    return `@${scope}/create` + (version ? `@${version}` : '')
  }
  const r = npa(initer)
  if (r.type === 'git' && r.hosted) {
    const { user, project } = r.hosted
    return initer.replace(`${user}/${project}`, `${user}/create-${project}`)
  }
  if (r.registry) return `${r.name.replace(/^(@[^/]+\/)?/, '$1create-')}@${r.rawSpec}`
  return initer
}

function kind (spec) {
  const r = npa(spec)
  const t = r.type === 'alias' ? r.subSpec.type : r.type
  if (['tag', 'version', 'range'].includes(t)) return 'registry'
  if (['file', 'directory'].includes(t)) return 'local'
  return 'remote' // git, remote tarball URLs, anything npm fetches from elsewhere
}

async function main () {
  const argv = tool === 'npx' ? npxToExec(userArgs) : userArgs
  const config = new Config({ npmPath: npmRoot, definitions, flatten, shorthands, argv: [process.execPath, 'npm', ...argv] })
  await config.load()
  const remain = [...config.parsedArgv.remain]
  projectPrefix = config.localPrefix || process.cwd()
  const raw = remain.shift()
  const command = raw === undefined ? null : (deref(raw) || null)
  let specs = []
  const inspect = []
  if (command && INSTALL.has(command)) {
    specs = remain.map(projectSpec)
  } else if (command === 'link') {
    // `npm link <name>` installs <name> globally from the registry when it is not linked yet (link.js)
    specs = remain.filter((x) => { try { return npa(x).type !== 'directory' } catch (e) { return true } })
  } else if (command && INSPECT.has(command)) {
    inspect.push(...(command === 'cache' ? remain.slice(1) : remain), ...[].concat(config.get('diff') || []))
  } else if (command && EXEC.has(command)) {
    const pkgs = [].concat(config.get('package') || [])
    specs = pkgs.length ? pkgs : remain.slice(0, 1)
  } else if (command && INIT.has(command) && remain.length) {
    specs = [createPackage(remain[0])]
  }
  const flat = { ...config.flat }
  let before = null
  try {
    before = config.get('before') ? new Date(config.get('before')).toISOString() : null
  } catch (e) {
    before = 'invalid'
  }
  const resolved = []
  if (command && !READ_ONLY.has(command)) {
    if (process.env.GK_TRUST_PROJECT_REGISTRY !== '1') {
      for (const spec of projectRegistries(config)) {
        resolved.push({ spec: `${spec} (project .npmrc)`, type: 'remote', error: 'registry set by the project' })
      }
    }
    for (const spec of offRegistryLockEntries(flat, config.localPrefix || process.cwd())) {
      resolved.push({ spec, type: 'remote', error: 'locked outside the registry' })
    }
  }
  for (const spec of inspect) {
    let type
    try { type = kind(spec) } catch (e) { type = 'invalid' }
    if (type === 'remote' || type === 'invalid') resolved.push({ spec, type })
  }
  for (const spec of specs) {
    if (!spec) {
      resolved.push({ spec, type: 'invalid', error: 'empty package spec' })
      continue
    }
    let type
    try {
      type = kind(spec)
    } catch (e) {
      resolved.push({ spec, type: 'invalid', error: String(e.message || e) })
      continue
    }
    if (type !== 'registry') {
      resolved.push({ spec, type })
      continue
    }
    try {
      // the version npm would pick, with the user's registry, scoped registries, tag and before settings
      // The arguments are the final ones, including Gatekeeper's --before, so npm's own precedence decides
      // which cutoff applies and this is the version the install will get. When nothing is old enough, npm
      // would fail; resolve without the cutoff to name the version, which the guard then holds.
      let mani
      let requested = null
      try {
        mani = await pacoteMod().manifest(spec, { ...flat, fullMetadata: true })
        if (flat.before) {
          const latest = await pacoteMod().manifest(spec, { ...flat, before: null, fullMetadata: true })
          if (latest.version !== mani.version) requested = latest.version
        }
      } catch (e) {
        if (!flat.before || e.code !== 'ETARGET') throw e
        mani = await pacoteMod().manifest(spec, { ...flat, before: null, fullMetadata: true })
      }
      const pack = await pacoteMod().packument(mani.name, { ...flat, fullMetadata: true })
      const deps = []
      for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
        for (const [k, v] of Object.entries(mani[section] || {})) deps.push([k, v])
      }
      resolved.push({
        spec,
        type,
        name: mani.name,
        version: mani.version,
        tarball: mani._resolved || (mani.dist && mani.dist.tarball),
        integrity: mani._integrity || (mani.dist && mani.dist.integrity),
        time: pack.time || {},
        dependencies: deps,
        requested_version: requested,
      })
    } catch (e) {
      resolved.push({ spec, type, error: String(e.code || '') + ' ' + String(e.message || e).slice(0, 300) })
    }
  }
  process.stdout.write(JSON.stringify({
    command, raw: raw === undefined ? null : raw, positionals: remain, specs: resolved,
    before,
  }))
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String((e && e.message) || e) }))
  process.exitCode = 1
})
