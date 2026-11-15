-- ============================================================================
--  GG SPY  -  espião de chamadas do GameGuardian
--  Executa o script ORIGINAL e registra tudo que ele faz com a API gg.*,
--  enquanto reconstrói um script legível (spy_reconstruido.lua) em tempo real.
--
--  USO: no GameGuardian, selecione o jogo/processo, execute ESTE arquivo.
--       Ele pergunta o caminho do script original e roda por cima.
--
--  ARQUIVOS GERADOS (em gg.EXT_STORAGE, normalmente /sdcard):
--    spy_log.txt            registro cronológico detalhado (args, retornos, erros)
--    spy_reconstruido.lua   chamadas gg.* em formato de script (com nomes das constantes)
--    spy_payload_N.lua      qualquer código passado a load/loadstring (decifrado!)
--
--  MODO SEGURO (padrão): bloqueia o que ALTERA coisas (editar/congelar memória,
--  velocidade, matar processo, rede, os.execute, apagar/renomear arquivos).
--  Buscas, menus, leituras e toasts continuam funcionando normalmente.
--  MODO PASSIVO: só registra, nada é bloqueado (use por sua conta e risco).
--
--  IMPORTANTE: este script NÃO cria variáveis globais e NÃO adiciona chaves em
--  _G nem em gg (só troca o valor de chaves existentes). Isso é proposital:
--  scripts protegidos costumam "impressionar" o ambiente pela ordem das chaves.
-- ============================================================================

do
  -- ---------------------------- CONFIGURAÇÃO --------------------------------
  local TARGET = "/sdcard/com.mobile.legends.lua"   -- script original
  local ASK    = true      -- true = pergunta caminho e modo ao iniciar
  local SAFE   = true      -- true = modo seguro (veja acima)
  local MAXSTR = 400       -- tamanho máximo de strings no spy_log.txt
  -- --------------------------------------------------------------------------

  -- tudo capturado ANTES de qualquer troca
  local gg, io, os, string, table, math = gg, io, os, string, table, math
  local io_open, os_clock, os_time, os_date = io.open, os.clock, os.time, os.date
  local pcall, xpcall, pairs, ipairs, type, tostring, tonumber, select, error =
        pcall, xpcall, pairs, ipairs, type, tostring, tonumber, select, error
  local unpack = table.unpack or unpack
  local fmt, srep, ssub, sgsub = string.format, string.rep, string.sub, string.gsub
  local tconcat, tsort = table.concat, table.sort
  local band = (bit32 and bit32.band) or nil
  local gg_toast, gg_alert = gg.toast, gg.alert   -- versões originais (não registradas)
  local _load, _loadstring, _loadfile, _dofile, _print, _require =
        load, loadstring, loadfile, dofile, print, require

  local base = gg.EXT_STORAGE or "/sdcard"
  local F_LOG   = base .. "/spy_log.txt"
  local F_RECON = base .. "/spy_reconstruido.lua"

  if ASK then
    local r = gg.prompt({ "Caminho do script original:" }, { TARGET }, { "text" })
    if not r then return end
    TARGET = r[1]
    local m = gg.choice({
      "Modo SEGURO (bloqueia alterações) - recomendado",
      "Modo PASSIVO (só registra, nada é bloqueado)",
    }, 1, "GG Spy")
    if not m then return end
    SAFE = (m == 1)
  end

  -- ---------------------------- ARQUIVOS ------------------------------------
  local flog   = assert(io_open(F_LOG, "w"))
  local frecon = assert(io_open(F_RECON, "w"))
  local t0 = os_clock()
  local callno, payloadno = 0, 0
  local counts = {}

  local function wlog(s)
    flog:write(fmt("[%8.3f] %s\n", os_clock() - t0, s)); flog:flush()
  end
  local function wrecon(s) frecon:write(s, "\n"); frecon:flush() end

  -- ---------------------------- CONSTANTES ----------------------------------
  local CONST = { TYPE = {}, SIGN = {}, REGION = {}, LOAD = {}, SAVE = {}, POINTER = {}, PROT = {}, ASM = {}, FREEZE = {} }
  local REGIONS = {}
  for k, v in pairs(gg) do
    if type(k) == "string" and type(v) == "number" then
      local p = k:match("^([A-Z]+)_")
      if p and CONST[p] then
        CONST[p][v] = CONST[p][v] or ("gg." .. k)
        if p == "REGION" then REGIONS[#REGIONS + 1] = { k = "gg." .. k, v = v } end
      end
    end
  end
  tsort(REGIONS, function(a, b) return a.v < b.v end)

  local function const_name(kind, v)
    if type(v) ~= "number" then return nil end
    if kind == "REGION" and band then
      local parts, rest = {}, v
      for _, r in ipairs(REGIONS) do
        if r.v ~= 0 and band(v, r.v) == r.v then parts[#parts + 1] = r.k; rest = rest - r.v end
      end
      if #parts > 0 and rest == 0 then return tconcat(parts, " + ") end
      return nil
    end
    return CONST[kind] and CONST[kind][v]
  end

  -- onde cada função recebe constantes (índice do argumento -> grupo)
  local SPEC = {
    searchNumber  = { [2] = "TYPE", [4] = "SIGN" },
    refineNumber  = { [2] = "TYPE", [4] = "SIGN" },
    searchAddress = { [3] = "TYPE", [4] = "SIGN" },
    refineAddress = { [3] = "TYPE", [4] = "SIGN" },
    searchFuzzy   = { [2] = "SIGN", [3] = "TYPE" },
    startFuzzy    = { [1] = "TYPE" },
    editAll       = { [2] = "TYPE" },
    getResults    = { [7] = "TYPE" },
    setRanges     = { [1] = "REGION" },
    loadList      = { [2] = "LOAD" },
    saveList      = { [2] = "SAVE" },
    loadResults   = {},
  }

  -- ---------------------------- SERIALIZAÇÃO --------------------------------
  local function qstr(s, max)
    if max and #s > max then s = ssub(s, 1, max) .. "…(+" .. (#s - max) .. " bytes)" end
    return (sgsub(fmt("%q", s), "\\\n", "\\n"))
  end

  local function ser(v, max, depth, seen, ctx)
    local t = type(v)
    if t == "string" then return qstr(v, max)
    elseif t == "number" or t == "boolean" or t == "nil" then return tostring(v)
    elseif t == "table" then
      depth = depth or 0; seen = seen or {}
      if depth >= 4 then return "{…}" end
      if seen[v] then return "{<ciclo>}" end
      seen[v] = true
      local out, n, arr = {}, 0, #v
      for i = 1, arr do
        n = n + 1; if n > 30 then out[#out + 1] = "…(+" .. (arr - 30) .. ")"; break end
        out[#out + 1] = ser(v[i], max, depth + 1, seen, ctx)
      end
      if n <= 30 then
        local keys = {}
        for k in pairs(v) do
          if not (type(k) == "number" and k >= 1 and k <= arr and k % 1 == 0) then keys[#keys + 1] = k end
        end
        tsort(keys, function(a, b) return tostring(a) < tostring(b) end)
        for _, k in ipairs(keys) do
          n = n + 1; if n > 30 then out[#out + 1] = "…"; break end
          local val = v[k]
          local vs
          if k == "flags" and type(val) == "number" and CONST.TYPE[val] then vs = CONST.TYPE[val]
          elseif k == "address" and type(val) == "number" then vs = fmt("0x%X", val)
          else vs = ser(val, max, depth + 1, seen, ctx) end
          local ks = (type(k) == "string" and k:match("^[%a_][%w_]*$")) and k or ("[" .. ser(k, max) .. "]")
          out[#out + 1] = ks .. " = " .. vs
        end
      end
      seen[v] = nil
      return "{" .. tconcat(out, ", ") .. "}"
    elseif t == "function" then return "<função>"
    else return "<" .. t .. ">" end
  end

  local function pack(...) return { n = select("#", ...), ... } end

  local function fmt_args(name, a, full)
    local spec = SPEC[name] or {}
    local out = {}
    for i = 1, a.n do
      local s
      if spec[i] and const_name(spec[i], a[i]) then s = const_name(spec[i], a[i])
      else s = ser(a[i], full and 4000 or MAXSTR) end
      out[i] = s
    end
    return tconcat(out, ", ")
  end

  local function fmt_rets(r, full)
    local out = {}
    for i = 1, r.n do out[i] = ser(r[i], full and 2000 or MAXSTR) end
    return tconcat(out, ", ")
  end

  -- ---------------------------- BLOQUEIOS (modo seguro) ---------------------
  -- retorna valores "de sucesso" plausíveis para o script original continuar
  local BLOCK = {
    ["gg.editAll"]       = function() return 0 end,
    ["gg.setValues"]     = function() return true end,
    ["gg.setSpeed"]      = function() return true end,
    ["gg.timeJump"]      = function() return true end,
    ["gg.processKill"]   = function() return true end,
    ["gg.processPause"]  = function() return true end,
    ["gg.unrandomizer"]  = function() return true end,
    ["gg.copyMemory"]    = function() return true end,
    ["gg.allocatePage"]  = function() return 0 end,
    ["gg.makeRequest"]   = function() return { code = 0, content = "", headers = {}, url = "" } end,
    ["gg.addListItems"]  = function() return true end,
    ["gg.loadList"]      = function() return true end,
    ["os.execute"]       = function() return nil end,
    ["os.remove"]        = function() return nil, "bloqueado pelo spy" end,
    ["os.rename"]        = function() return nil, "bloqueado pelo spy" end,
    ["io.popen"]         = function() return nil, "bloqueado pelo spy" end,
  }

  -- ---------------------------- WRAPPER GENÉRICO ----------------------------
  local INTERACTIVE = { alert = 1, choice = 1, multiChoice = 1, prompt = 1 }

  local function wrap(qname, shortname, fn, isgg)
    return function(...)
      callno = callno + 1
      local id = callno
      counts[qname] = (counts[qname] or 0) + 1
      local a = pack(...)
      local argstr = fmt_args(shortname, a)
      if SAFE and BLOCK[qname] then
        local r = pack(BLOCK[qname](...))
        wlog(fmt("#%d %s(%s)  => BLOQUEADO (modo seguro) -> %s", id, qname, argstr, fmt_rets(r)))
        if isgg then
          wrecon(fmt("-- [BLOQUEADO pelo spy] %s(%s)", qname, fmt_args(shortname, a, true)))
        end
        return unpack(r, 1, r.n)
      end
      local r = pack(pcall(fn, ...))
      if not r[1] then
        wlog(fmt("#%d %s(%s)  => ERRO: %s", id, qname, argstr, tostring(r[2])))
        if isgg then wrecon(fmt("-- ERRO em %s: %s", qname, tostring(r[2]))) end
        error(r[2], 0)
      end
      local rr = pack(unpack(r, 2, r.n))
      wlog(fmt("#%d %s(%s)  => %s", id, qname, argstr, fmt_rets(rr)))
      if isgg then
        local call = fmt("%s(%s)", qname, fmt_args(shortname, a, true))
        if rr.n > 0 and rr[1] ~= nil then
          wrecon(fmt("R[%d] = %s  -- => %s", id, call, fmt_rets(rr, true)))
        else
          wrecon(call)
        end
      end
      return unpack(rr, 1, rr.n)
    end
  end

  -- ---------------------------- INSTALAÇÃO DOS HOOKS ------------------------
  wrecon("-- Script reconstruído pelo GG Spy a partir das chamadas observadas.")
  wrecon("-- Gerado em " .. os_date("%Y-%m-%d %H:%M:%S") .. "  |  origem: " .. TARGET)
  wrecon("-- R[n] guarda o retorno da chamada n; comentários '=>' mostram o valor real observado.")
  wrecon("-- Lógica (if/for/while) NÃO é inferida: isto é a SEQUÊNCIA do que aconteceu nesta execução.")
  wrecon("local R = {}")
  wrecon("")
  wlog("GG Spy iniciado. alvo=" .. TARGET .. " modo=" .. (SAFE and "SEGURO" or "PASSIVO"))

  -- gg.*  (só troca valores de chaves já existentes)
  local ggfuncs = {}
  for k, v in pairs(gg) do if type(v) == "function" then ggfuncs[#ggfuncs + 1] = k end end
  tsort(ggfuncs)
  for _, k in ipairs(ggfuncs) do gg[k] = wrap("gg." .. k, k, gg[k], true) end

  -- helpers para libs padrão (só se a chave já existir)
  local function hook(tbl, tname, key)
    if tbl and type(tbl[key]) == "function" then
      tbl[key] = wrap(tname .. key, key, tbl[key], false)
    end
  end
  hook(os, "os.", "execute"); hook(os, "os.", "remove"); hook(os, "os.", "rename")
  hook(os, "os.", "exit");    hook(os, "os.", "getenv")
  hook(io, "io.", "popen");   hook(io, "io.", "open")

  local function dump_payload(kind, src)
    payloadno = payloadno + 1
    local path = fmt("%s/spy_payload_%d.lua", base, payloadno)
    local f = io_open(path, "wb")
    if f then f:write(src); f:close() end
    wlog(fmt("%s: código dinâmico de %d bytes salvo em %s", kind, #src, path))
    wrecon(fmt("-- [%s] código carregado dinamicamente salvo em %s (%d bytes)", kind, path, #src))
  end

  if _loadstring then
    loadstring = function(s, ...)
      if type(s) == "string" then dump_payload("loadstring", s) end
      return _loadstring(s, ...)
    end
  end
  if _load then
    load = function(s, ...)
      if type(s) == "string" then dump_payload("load", s) end
      return _load(s, ...)
    end
  end
  if _loadfile then
    loadfile = function(p, ...)
      wlog("loadfile(" .. ser(p) .. ")"); wrecon("-- loadfile(" .. ser(p, 400) .. ")")
      return _loadfile(p, ...)
    end
  end
  if _dofile then
    dofile = function(p, ...)
      wlog("dofile(" .. ser(p) .. ")"); wrecon("-- dofile(" .. ser(p, 400) .. ")")
      return _dofile(p, ...)
    end
  end
  if _require then
    require = function(p, ...)
      wlog("require(" .. ser(p) .. ")"); wrecon("-- require(" .. ser(p, 400) .. ")")
      return _require(p, ...)
    end
  end
  if _print then
    print = function(...)
      local a = pack(...)
      wlog("print(" .. fmt_args("print", a) .. ")")
      return _print(...)
    end
  end

  -- ---------------------------- RESUMO --------------------------------------
  local function summary(reason)
    local names = {}
    for k in pairs(counts) do names[#names + 1] = k end
    tsort(names, function(a, b) return counts[a] > counts[b] end)
    wlog("=== FIM: " .. reason .. " | chamadas observadas: " .. callno .. " ===")
    wrecon("")
    wrecon("-- ===== FIM (" .. reason .. ") =====")
    wrecon("-- Resumo de chamadas:")
    for _, k in ipairs(names) do wrecon(fmt("--   %-24s x%d", k, counts[k])) end
    flog:flush(); frecon:flush()
  end

  -- ---------------------------- EXECUÇÃO DO ORIGINAL ------------------------
  local chunk, err = _loadfile(TARGET)
  if not chunk then
    wlog("FALHA ao carregar o original: " .. tostring(err))
    summary("falha ao carregar")
    gg_alert("GG Spy: não consegui carregar\n" .. TARGET .. "\n\n" .. tostring(err))
    return
  end
  gg_toast("GG Spy ativo (" .. (SAFE and "seguro" or "passivo") .. ")")
  local ok, e = xpcall(chunk, function(m) return tostring(m) end)
  if ok then summary("script terminou normalmente")
  else
    wlog("O script original terminou com erro: " .. tostring(e))
    summary("erro: " .. tostring(e))
  end
  flog:close(); frecon:close()
  gg_alert("GG Spy: concluído.\n\nLog: " .. F_LOG .. "\nScript reconstruído: " .. F_RECON)
end
