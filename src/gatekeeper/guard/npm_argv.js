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
const npa = req('npm-package-arg')
const pacote = req('pacote')
const { deref } = require(path.join(npmRoot, 'lib', 'utils', 'cmd-list.js'))

const INSTALL = new Set(['install', 'install-test', 'update'])
const EXEC = new Set(['exec'])
const INIT = new Set(['init'])

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
  const raw = remain.shift()
  const command = raw === undefined ? null : (deref(raw) || null)
  let specs = []
  if (command && INSTALL.has(command)) {
    specs = remain
  } else if (command && EXEC.has(command)) {
    const pkgs = [].concat(config.get('package') || [])
    specs = pkgs.length ? pkgs : remain.slice(0, 1)
  } else if (command && INIT.has(command) && remain.length) {
    specs = [createPackage(remain[0])]
  }
  const flat = { ...config.flat }
  const before = config.get('before')
  const resolved = []
  for (const spec of specs) {
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
      const mani = await pacote.manifest(spec, { ...flat, fullMetadata: true })
      const pack = await pacote.packument(mani.name, { ...flat, fullMetadata: true })
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
      })
    } catch (e) {
      resolved.push({ spec, type, error: String(e.code || '') + ' ' + String(e.message || e).slice(0, 300) })
    }
  }
  process.stdout.write(JSON.stringify({
    command, raw: raw === undefined ? null : raw, positionals: remain, specs: resolved,
    before: before ? new Date(before).toISOString() : null,
  }))
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String((e && e.message) || e) }))
  process.exitCode = 1
})
