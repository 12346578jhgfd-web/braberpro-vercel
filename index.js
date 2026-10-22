// ============================================================
// BARBERPRO - SERVIDOR PARA VERCEL (backend + banco Postgres)
// No Vercel o servidor "liga e desliga" a cada acesso e não guarda
// arquivos. Por isso os dados ficam num banco Postgres externo (Neon).
// ============================================================
const express = require('express');
const { Pool } = require('pg');             // conversa com o banco Postgres
const bcrypt = require('bcryptjs');          // embaralha senhas (hash)
const jwt = require('jsonwebtoken');         // "crachá" de login
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

// ---------- 1. BANCO DE DADOS ----------
// O Vercel cria a variável DATABASE_URL sozinho ao conectar o banco ao projeto.
const dbUrl = (process.env.DATABASE_URL || process.env.POSTGRES_URL || '')
  .replace('sslmode=require', 'sslmode=verify-full').replace(/[&?]channel_binding=[^&]*/, '');
// connectionTimeoutMillis = espera até 15s (o banco gratuito "acorda" devagar depois de parado)
const pool = new Pool({ connectionString: dbUrl, max: 3, connectionTimeoutMillis: 15000 });
const q = async (sql, p = []) => (await pool.query(sql, p)).rows;   // devolve a lista de linhas
const one = async (sql, p) => (await q(sql, p))[0];                 // devolve só a primeira linha
// tx = transação: executa vários comandos como um só (ou todos funcionam, ou nenhum)
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); const r = await fn((s, p = []) => c.query(s, p)); await c.query('COMMIT'); return r; }
  catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}

// Cria as tabelas (se não existirem) e o administrador. Roda quando o servidor "acorda".
async function init() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT, role TEXT, blocked INT DEFAULT 0, active INT DEFAULT 1);
  CREATE TABLE IF NOT EXISTS clients(id SERIAL PRIMARY KEY, name TEXT, phone TEXT, active INT DEFAULT 1);
  CREATE TABLE IF NOT EXISTS professionals(id SERIAL PRIMARY KEY, name TEXT, commission DOUBLE PRECISION, active INT DEFAULT 1);
  CREATE TABLE IF NOT EXISTS services(id SERIAL PRIMARY KEY, name TEXT, price DOUBLE PRECISION, active INT DEFAULT 1);
  CREATE TABLE IF NOT EXISTS appointments(id SERIAL PRIMARY KEY, client_id INT REFERENCES clients(id), professional_id INT REFERENCES professionals(id),
    service_id INT REFERENCES services(id), date TEXT, time TEXT, price DOUBLE PRECISION, status TEXT DEFAULT 'agendado');
  CREATE TABLE IF NOT EXISTS cash_sessions(id SERIAL PRIMARY KEY, opened_at TEXT, closed_at TEXT, opening DOUBLE PRECISION, closing DOUBLE PRECISION);
  CREATE TABLE IF NOT EXISTS cash(id SERIAL PRIMARY KEY, session_id INT REFERENCES cash_sessions(id), type TEXT, description TEXT, amount DOUBLE PRECISION, created_at TEXT, appointment_id INT);`);
  const em = process.env.ADMIN_EMAIL, pw = process.env.ADMIN_PASSWORD;
  if (em && pw) {
    // Com as variáveis definidas, a senha do admin é sempre igual a ADMIN_PASSWORD
    await q(`INSERT INTO users(name,email,password_hash,role) VALUES('Administrador',$1,$2,'admin')
      ON CONFLICT(email) DO UPDATE SET password_hash=$2, role='admin', blocked=0, active=1`, [em, bcrypt.hashSync(pw, 10)]);
  } else if (!(await one("SELECT 1 x FROM users WHERE role='admin'"))) {   // sem variáveis: usa o login do PDF
    await q("INSERT INTO users(name,email,password_hash,role) VALUES('Administrador','admin@projeto.com.br',$1,'admin')", [bcrypt.hashSync('Admin@2026#TCC', 10)]);
  }
}
// Tenta iniciar o banco até 4 vezes (o Neon gratuito pode demorar a acordar).
// Se falhar tudo, NÃO guarda a falha: o próximo acesso tenta de novo.
let ready = null;
async function initRetry() {
  for (let i = 1; i <= 4; i++) {
    try { return await init(); }
    catch (e) { console.error('Tentativa ' + i + ' de conectar ao banco falhou:', e.message); if (i === 4) throw e; await new Promise(r => setTimeout(r, 2000)); }
  }
}
const start = () => ready || (ready = initRetry().catch(e => { ready = null; throw e; }));
start().catch(() => {});

// ---------- 2. FUNÇÕES AUXILIARES ----------
// Chave do crachá: usa JWT_SECRET; se não existir, deriva uma chave fixa da URL do banco
const SECRET = process.env.JWT_SECRET || crypto.createHash('sha256').update(process.env.DATABASE_URL || 'dev').digest('hex');
const now = () => new Date(Date.now() - 3 * 3600e3).toISOString().slice(0, 19).replace('T', ' '); // hora do Brasil
const bad = (res, msg) => res.status(400).json({ erro: msg });
const ROLES = ['admin', 'gerente', 'operador'];
// wrap: captura erros das rotas assíncronas e devolve mensagem amigável
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  if (['23505', '23503'].includes(e.code)) return bad(res, 'Dados inválidos ou já cadastrados');
  res.status(500).json({ erro: 'Erro interno' });
});

// ---------- 3. SEGURANÇA ----------
// auth: roda antes de toda rota protegida; confere o crachá e se o usuário não está bloqueado
async function auth(req, res, next) {
  try {
    const { id } = jwt.verify(req.cookies.token, SECRET);
    const u = await one('SELECT id,name,email,role,blocked,active FROM users WHERE id=$1', [id]);
    if (!u || u.blocked || !u.active) throw new Error('inválido');
    req.user = u; next();
  } catch { res.status(401).json({ erro: 'Sessão inválida' }); }
}
// need: só deixa passar os perfis listados (a verificação é feita AQUI, no servidor)
const need = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ erro: 'Sem permissão' });

const app = express();
app.set('trust proxy', 1);
app.use(express.json(), cookieParser());
// Entrega a tela do site. Procura a pasta "public" em vários lugares (o Vercel muda o caminho).
for (const d of [path.join(__dirname, 'public'), path.join(__dirname, '..', 'public'), path.join(process.cwd(), 'public')]) app.use(express.static(d));
app.use((req, res, next) => start().then(() => next(), () => res.status(500).json({ erro: 'Banco de dados indisponível' })));

app.post('/api/login', wrap(async (req, res) => {
  const { email = '', password = '' } = req.body;
  const u = await one('SELECT * FROM users WHERE lower(email)=lower($1) AND active=1', [String(email).trim()]);
  if (!u || !bcrypt.compareSync(String(password), u.password_hash)) return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
  if (u.blocked) return res.status(403).json({ erro: 'Conta bloqueada. Procure o administrador.' });
  res.cookie('token', jwt.sign({ id: u.id }, SECRET, { expiresIn: '8h' }), { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 8 * 3600e3 });
  res.json({ ok: 1 });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: 1 }); });

app.use('/api', auth);   // tudo abaixo desta linha exige login
app.get('/api/me', (req, res) => res.json(req.user));

// ---------- 4. USUÁRIOS (somente administrador) ----------
const U = express.Router();
U.use(need('admin'));
U.get('/', wrap(async (req, res) => res.json(await q('SELECT id,name,email,role,blocked FROM users WHERE active=1 ORDER BY name'))));
U.post('/', wrap(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !ROLES.includes(role) || String(password || '').length < 8) return bad(res, 'Preencha tudo. A senha precisa ter 8+ caracteres.');
  await q('INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4)', [name.trim(), email.trim(), bcrypt.hashSync(password, 10), role]);
  res.json({ ok: 1 });
}));
U.put('/:id', wrap(async (req, res) => {
  const { name, email, role } = req.body;
  if (!name || !email || !ROLES.includes(role)) return bad(res, 'Dados inválidos');
  if (req.params.id == req.user.id && role !== 'admin') return bad(res, 'Você não pode tirar seu próprio acesso de admin');
  await q('UPDATE users SET name=$1,email=$2,role=$3 WHERE id=$4', [name.trim(), email.trim(), role, req.params.id]);
  res.json({ ok: 1 });
}));
const notSelf = (req, res) => req.params.id == req.user.id && (bad(res, 'Não é possível fazer isso com a própria conta'), true);
U.post('/:id/block', wrap(async (req, res) => { if (notSelf(req, res)) return; await q('UPDATE users SET blocked=1 WHERE id=$1', [req.params.id]); res.json({ ok: 1 }); }));
U.post('/:id/unblock', wrap(async (req, res) => { await q('UPDATE users SET blocked=0 WHERE id=$1', [req.params.id]); res.json({ ok: 1 }); }));
U.delete('/:id', wrap(async (req, res) => { if (notSelf(req, res)) return; await q('UPDATE users SET active=0, blocked=1 WHERE id=$1', [req.params.id]); res.json({ ok: 1 }); }));
U.post('/:id/reset', wrap(async (req, res) => {   // gera senha temporária aleatória
  const senha = crypto.randomBytes(5).toString('hex') + 'A1!';
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [bcrypt.hashSync(senha, 10), req.params.id]);
  res.json({ senha });
}));
app.use('/api/usuarios', U);

// ---------- 5. CADASTROS (clientes, profissionais, serviços) ----------
// "Excluir" só desativa (active=0) para não quebrar o histórico.
function crud(table, fields, writers) {
  const r = express.Router();
  const valid = b => fields.every(f => String(b[f] ?? '').trim() !== '') &&
    (!('price' in b) || Number(b.price) >= 0) && (!('commission' in b) || (Number(b.commission) >= 0 && Number(b.commission) <= 100));
  r.get('/', wrap(async (req, res) => res.json(await q(`SELECT * FROM ${table} WHERE active=1 AND name ILIKE $1 ORDER BY name`, ['%' + (req.query.q || '') + '%']))));
  r.post('/', need(...writers), wrap(async (req, res) => {
    if (!valid(req.body)) return bad(res, 'Preencha os campos corretamente');
    await q(`INSERT INTO ${table}(${fields}) VALUES(${fields.map((_, i) => '$' + (i + 1))})`, fields.map(f => req.body[f]));
    res.json({ ok: 1 });
  }));
  r.put('/:id', need(...writers), wrap(async (req, res) => {
    if (!valid(req.body)) return bad(res, 'Preencha os campos corretamente');
    await q(`UPDATE ${table} SET ${fields.map((f, i) => f + '=$' + (i + 1))} WHERE id=$${fields.length + 1}`, [...fields.map(f => req.body[f]), req.params.id]);
    res.json({ ok: 1 });
  }));
  r.delete('/:id', need(...writers), wrap(async (req, res) => { await q(`UPDATE ${table} SET active=0 WHERE id=$1`, [req.params.id]); res.json({ ok: 1 }); }));
  return r;
}
app.use('/api/clientes', crud('clients', ['name', 'phone'], ROLES));
app.use('/api/profissionais', crud('professionals', ['name', 'commission'], ['admin', 'gerente']));
app.use('/api/servicos', crud('services', ['name', 'price'], ['admin', 'gerente']));

// ---------- 6. CAIXA ----------
const openCash = () => one('SELECT * FROM cash_sessions WHERE closed_at IS NULL');
const totals = async s => {
  const sum = async t => (await one('SELECT COALESCE(SUM(amount),0) v FROM cash WHERE session_id=$1 AND type=$2', [s.id, t])).v;
  const receitas = await sum('receita'), despesas = await sum('despesa');
  return { receitas, despesas, saldo: s.opening + receitas - despesas };
};
const C = express.Router();
C.use(need('admin', 'gerente'));
C.get('/', wrap(async (req, res) => {
  const s = await openCash();
  if (!s) return res.json({ aberto: null });
  res.json({ aberto: s, ...(await totals(s)), entries: await q('SELECT * FROM cash WHERE session_id=$1 ORDER BY id DESC', [s.id]) });
}));
C.post('/abrir', wrap(async (req, res) => {
  if (await openCash()) return bad(res, 'Já existe um caixa aberto');
  const v = Number(req.body.valor);
  if (!(v >= 0)) return bad(res, 'Valor inválido');
  await q('INSERT INTO cash_sessions(opened_at,opening) VALUES($1,$2)', [now(), v]);
  res.json({ ok: 1 });
}));
C.post('/despesa', wrap(async (req, res) => {
  const s = await openCash(), v = Number(req.body.amount);
  if (!s) return bad(res, 'Abra o caixa primeiro');
  if (!req.body.description || !(v > 0)) return bad(res, 'Informe descrição e valor maior que zero');
  await q('INSERT INTO cash(session_id,type,description,amount,created_at) VALUES($1,$2,$3,$4,$5)', [s.id, 'despesa', req.body.description.trim(), v, now()]);
  res.json({ ok: 1 });
}));
C.post('/fechar', wrap(async (req, res) => {
  const s = await openCash();
  if (!s) return bad(res, 'Não há caixa aberto');
  await q('UPDATE cash_sessions SET closed_at=$1, closing=$2 WHERE id=$3', [now(), (await totals(s)).saldo, s.id]);
  res.json({ ok: 1 });
}));
app.use('/api/caixa', C);

// ---------- 7. AGENDA ----------
const A = express.Router();
A.get('/', wrap(async (req, res) => res.json(await q(`
  SELECT a.*, c.name client, p.name professional, s.name service FROM appointments a
  JOIN clients c ON c.id=a.client_id JOIN professionals p ON p.id=a.professional_id
  JOIN services s ON s.id=a.service_id WHERE a.date=$1 ORDER BY a.time`, [req.query.date || now().slice(0, 10)]))));
A.post('/', wrap(async (req, res) => {
  const { client_id, professional_id, service_id, date, time } = req.body;
  const s = await one('SELECT price FROM services WHERE id=$1 AND active=1', [service_id]);
  if (!s || !client_id || !professional_id || !date || !time) return bad(res, 'Dados inválidos');
  if (await one("SELECT 1 x FROM appointments WHERE professional_id=$1 AND date=$2 AND time=$3 AND status!='cancelado'", [professional_id, date, time]))
    return res.status(409).json({ erro: 'Profissional já tem agendamento neste horário' });
  await q('INSERT INTO appointments(client_id,professional_id,service_id,date,time,price) VALUES($1,$2,$3,$4,$5,$6)', [client_id, professional_id, service_id, date, time, s.price]);
  res.json({ ok: 1 });
}));
A.post('/:id/cancelar', wrap(async (req, res) => {
  await q("UPDATE appointments SET status='cancelado' WHERE id=$1 AND status='agendado'", [req.params.id]);
  res.json({ ok: 1 });
}));
// Cancelar TODOS os pendentes (do dia mostrado, ou de todas as datas). Concluídos não são mexidos.
A.post('/cancelar-todos', need('admin', 'gerente'), wrap(async (req, res) => {
  const r = req.body.todas
    ? await pool.query("UPDATE appointments SET status='cancelado' WHERE status='agendado'")
    : await pool.query("UPDATE appointments SET status='cancelado' WHERE status='agendado' AND date=$1", [req.body.date || now().slice(0, 10)]);
  res.json({ cancelados: r.rowCount });
}));
// Cancelar CONCLUÍDOS: cada um gera um ESTORNO (despesa) no caixa aberto
A.post('/cancelar-concluidos', need('admin', 'gerente'), wrap(async (req, res) => {
  const cx = await openCash();
  if (!cx) return bad(res, 'Abra o caixa para registrar os estornos');
  const base = "SELECT a.id, a.price, s.name FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.status='concluido'";
  const lista = req.body.todas ? await q(base) : await q(base + ' AND a.date=$1', [req.body.date || now().slice(0, 10)]);
  await tx(async c => {
    for (const a of lista) {
      await c("UPDATE appointments SET status='cancelado' WHERE id=$1", [a.id]);
      await c('INSERT INTO cash(session_id,type,description,amount,created_at,appointment_id) VALUES($1,$2,$3,$4,$5,$6)', [cx.id, 'despesa', 'Estorno: ' + a.name + ' (cancelado)', a.price, now(), a.id]);
    }
  });
  res.json({ cancelados: lista.length });
}));
// Concluir = marca como feito + lança a RECEITA no caixa (tudo ou nada)
A.post('/:id/concluir', wrap(async (req, res) => {
  const a = await one('SELECT a.*, s.name sname FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.id=$1', [req.params.id]);
  const cx = await openCash();
  if (!a || a.status !== 'agendado') return bad(res, 'Agendamento não disponível');
  if (!cx) return bad(res, 'Peça ao gerente para abrir o caixa antes de concluir atendimentos');
  await tx(async c => {
    await c("UPDATE appointments SET status='concluido' WHERE id=$1", [a.id]);
    await c('INSERT INTO cash(session_id,type,description,amount,created_at,appointment_id) VALUES($1,$2,$3,$4,$5,$6)', [cx.id, 'receita', a.sname, a.price, now(), a.id]);
  });
  res.json({ ok: 1 });
}));
app.use('/api/agenda', A);

// ---------- 8. PAINEL E RELATÓRIOS ----------
app.get('/api/dashboard', need('admin', 'gerente'), wrap(async (req, res) => {
  const mes = (/^\d{4}-\d{2}$/.test(req.query.mes) ? req.query.mes : now().slice(0, 7)) + '%', hoje = now().slice(0, 10);
  const soma = async t => (await one('SELECT COALESCE(SUM(amount),0) v FROM cash WHERE type=$1 AND created_at LIKE $2', [t, mes])).v;
  res.json({
    hoje: (await one("SELECT COUNT(*)::int n FROM appointments WHERE date=$1 AND status!='cancelado'", [hoje])).n,
    receita: await soma('receita'), despesa: await soma('despesa'),
    comissoes: await q(`SELECT p.name, COUNT(*)::int n, SUM(a.price) total, ROUND((SUM(a.price)*p.commission/100)::numeric,2)::float8 comissao
      FROM appointments a JOIN professionals p ON p.id=a.professional_id WHERE a.status='concluido' AND a.date LIKE $1 GROUP BY p.id`, [mes]),
    top: await q(`SELECT s.name, COUNT(*)::int n, SUM(a.price) total FROM appointments a JOIN services s ON s.id=a.service_id
      WHERE a.status='concluido' AND a.date LIKE $1 GROUP BY s.id ORDER BY n DESC`, [mes]),
  });
}));

// Download de relatórios em CSV (abre no Excel): /api/relatorio/financeiro?de=...&ate=...
const csvCell = v => {
  let s = typeof v === 'number' ? String(v).replace('.', ',') : String(v ?? '');
  if (/^[=+\-@]/.test(s)) s = "'" + s;   // evita "injeção de fórmula" no Excel
  return '"' + s.replace(/"/g, '""') + '"';
};
const REL = {
  servicos_mensal: { titulo: 'Mês;Serviço;Quantidade;Total', sql: `SELECT substr(a.date,1,7), s.name, COUNT(*)::int, SUM(a.price)
    FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.status='concluido' AND a.date BETWEEN $1 AND $2
    GROUP BY substr(a.date,1,7), s.id ORDER BY 1, 3 DESC` },
  financeiro: { titulo: 'Data;Tipo;Descrição;Valor', sql: `SELECT created_at, type, description, amount FROM cash
    WHERE substr(created_at,1,10) BETWEEN $1 AND $2 ORDER BY created_at` },
  atendimentos: { titulo: 'Data;Hora;Cliente;Profissional;Serviço;Valor;Status', sql: `SELECT a.date, a.time, c.name, p.name, s.name, a.price, a.status
    FROM appointments a JOIN clients c ON c.id=a.client_id JOIN professionals p ON p.id=a.professional_id
    JOIN services s ON s.id=a.service_id WHERE a.date BETWEEN $1 AND $2 ORDER BY a.date, a.time` },
};
app.get('/api/relatorio/:tipo', need('admin', 'gerente'), wrap(async (req, res) => {
  const rel = REL[req.params.tipo];
  if (!rel) return bad(res, 'Relatório inexistente');
  const de = req.query.de || '2000-01-01', ate = req.query.ate || '2999-12-31';
  const { rows } = await pool.query({ text: rel.sql, values: [de, ate], rowMode: 'array' });   // cada linha vira uma lista
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${req.params.tipo}_${de}_a_${ate}.csv"` });
  res.send('\ufeff' + [rel.titulo, ...rows.map(l => l.map(csvCell).join(';'))].join('\r\n'));
}));

// ---------- 9. EXPORTAR ----------
// O Vercel usa o "app" exportado. Rodando localmente (node api/index.js), liga na porta 3000.
module.exports = app;
if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('BarberPro rodando!'));
