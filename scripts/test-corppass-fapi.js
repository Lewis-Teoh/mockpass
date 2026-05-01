#!/usr/bin/env node
/**
 * End-to-end smoke test for the CorpPass FAPI 2.0 flow.
 *
 * Prerequisites: MockPass running on PORT (default 5156).
 *
 *   PORT=5156 node index.js   (in one terminal)
 *   node scripts/test-corppass-fapi.js   (in another)
 *
 * Exercises: PAR -> auth (custom profile) -> token -> userinfo.
 * Verifies the userinfo response carries an auth_info payload shaped per
 * CorpPass spec (Result_Set -> ESrvc_Result -> Auth_Result_Set -> Row).
 */
const crypto = require('crypto')
const jose = require('jose')
const fs = require('fs')
const path = require('path')

const BASE = process.env.MOCKPASS_BASE || 'http://localhost:5156'
const IDP_BASE = `${BASE}/corppass/v3/fapi`
const REDIRECT_URI = 'http://localhost:3001/callback'
const CLIENT_ID = 'mock-fapi-client-id'

// Sample profile (matches an entry in lib/assertions.js → oidc.corpPass)
const TEST_PROFILE = {
  nric: 'S8979373D',
  uuid: 'a9865837-7bd7-46ac-bef4-42a76a946424',
  uen: '123456789A',
}

const FAPI_RP_PRIVATE_JWKS = path.resolve(
  __dirname,
  '../static/certs/fapi-rp-private.json',
)
const FAPI_ASP_PUBLIC_JWKS = path.resolve(
  __dirname,
  '../static/certs/fapi-asp-public.json',
)

function generatePkce() {
  const code_verifier = crypto.randomBytes(48).toString('base64url')
  const code_challenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url')
  return { code_verifier, code_challenge }
}

function randString(len) {
  return crypto.randomBytes(len).toString('base64url').slice(0, len)
}

async function getTestTokens(endpoint, ephemeralPrivateKey) {
  const body = { endpoint }
  if (ephemeralPrivateKey) body.ephemeralPrivateKey = ephemeralPrivateKey
  const res = await fetch(`${IDP_BASE}/tests/generate-tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`generate-tokens failed: ${await res.text()}`)
  return await res.json()
}

async function decryptIdToken(encrypted) {
  const rpJwks = JSON.parse(fs.readFileSync(FAPI_RP_PRIVATE_JWKS, 'utf8'))
  const rpEncKey = rpJwks.keys.find((k) => k.use === 'enc')
  const key = await jose.importJWK(rpEncKey, rpEncKey.alg)
  const { plaintext } = await jose.compactDecrypt(encrypted, key)
  // plaintext is a JWS — extract claims
  const jws = new TextDecoder().decode(plaintext)
  const claims = JSON.parse(
    Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'),
  )
  return claims
}

async function verifyUserInfo(jwt) {
  const aspJwks = JSON.parse(fs.readFileSync(FAPI_ASP_PUBLIC_JWKS, 'utf8'))
  const aspKeyset = jose.createLocalJWKSet(aspJwks)
  const { payload } = await jose.jwtVerify(jwt, aspKeyset)
  return payload
}

;(async () => {
  console.log(`\n=== CorpPass FAPI 2.0 e2e test ===`)
  console.log(`Target: ${IDP_BASE}\n`)

  const { code_verifier, code_challenge } = generatePkce()
  const state = randString(40)
  const nonce = randString(40)

  // 1. PAR
  console.log('1. POST /par ...')
  const parTokens = await getTestTokens(`${IDP_BASE}/par`)
  const parBody = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid authinfo',
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
    client_assertion_type:
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: parTokens.clientAssertionToken,
  })
  const parRes = await fetch(`${IDP_BASE}/par`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      DPoP: parTokens.dpopToken,
    },
    body: parBody,
  })
  if (!parRes.ok) {
    throw new Error(`PAR failed [${parRes.status}]: ${await parRes.text()}`)
  }
  const { request_uri } = await parRes.json()
  console.log(`   ✓ request_uri obtained: ${request_uri.slice(0, 60)}...`)

  // 2. Auth (custom profile — bypass interactive UI)
  console.log('2. GET /auth/custom-profile (skip UI) ...')
  const authUrl = new URL(`${IDP_BASE}/auth/custom-profile`)
  authUrl.searchParams.set('request_uri', request_uri)
  authUrl.searchParams.set('nric', TEST_PROFILE.nric)
  authUrl.searchParams.set('uuid', TEST_PROFILE.uuid)
  authUrl.searchParams.set('uen', TEST_PROFILE.uen)
  const authRes = await fetch(authUrl.toString(), { redirect: 'manual' })
  if (authRes.status !== 302) {
    throw new Error(`Auth failed [${authRes.status}]: ${await authRes.text()}`)
  }
  const location = authRes.headers.get('location')
  const code = new URL(location).searchParams.get('code')
  if (!code) throw new Error(`No auth code in redirect: ${location}`)
  console.log(`   ✓ auth code obtained: ${code.slice(0, 30)}...`)

  // 3. Token exchange
  console.log('3. POST /token ...')
  const tokenTokens = await getTestTokens(
    `${IDP_BASE}/token`,
    parTokens.ephemeralPrivateKey,
  )
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier,
    client_assertion_type:
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: tokenTokens.clientAssertionToken,
  })
  const tokenRes = await fetch(`${IDP_BASE}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      DPoP: tokenTokens.dpopToken,
    },
    body: tokenBody,
  })
  if (!tokenRes.ok) {
    throw new Error(
      `Token failed [${tokenRes.status}]: ${await tokenRes.text()}`,
    )
  }
  const { access_token, id_token, token_type } = await tokenRes.json()
  console.log(`   ✓ token_type: ${token_type}`)
  console.log(`   ✓ access_token: ${access_token.slice(0, 30)}...`)
  console.log(`   ✓ id_token: ${id_token.slice(0, 30)}... (encrypted JWE)`)

  // 4. Decrypt id_token, check shape
  console.log('4. Decrypt id_token ...')
  const idClaims = await decryptIdToken(id_token)
  console.log(`   ✓ sub: ${idClaims.sub}`)
  console.log(`   ✓ aud: ${idClaims.aud}`)
  console.log(`   ✓ iss: ${idClaims.iss}`)
  console.log(`   ✓ EntityInfo.CPEntID: ${idClaims.EntityInfo?.CPEntID}`)
  if (!idClaims.EntityInfo) {
    throw new Error('id_token missing EntityInfo claim (CorpPass-specific)')
  }
  if (idClaims.sub_attributes) {
    throw new Error(
      'id_token unexpectedly contains Singpass sub_attributes — CorpPass shape leaked',
    )
  }

  // 5. Userinfo
  console.log('5. GET /userinfo ...')
  const userinfoRes = await fetch(`${IDP_BASE}/userinfo`, {
    headers: { Authorization: `Bearer ${access_token}` },
  })
  if (!userinfoRes.ok) {
    throw new Error(
      `Userinfo failed [${userinfoRes.status}]: ${await userinfoRes.text()}`,
    )
  }
  const userinfoJwt = await userinfoRes.text()
  console.log(`   ✓ JWS received: ${userinfoJwt.slice(0, 30)}...`)

  // 6. Verify userinfo signature, extract claims
  console.log('6. Verify userinfo JWS + extract auth_info ...')
  const userinfoClaims = await verifyUserInfo(userinfoJwt)
  console.log(`   ✓ sub: ${userinfoClaims.sub}`)
  if (!userinfoClaims.auth_info) {
    throw new Error('userinfo missing auth_info claim')
  }
  const authInfo = JSON.parse(userinfoClaims.auth_info)
  const row = authInfo.Result_Set?.ESrvc_Result?.[0]?.Auth_Result_Set?.Row?.[0]
  if (!row) throw new Error('auth_info malformed: no Row[0]')
  console.log(
    `   ✓ CPESrvcID:    ${authInfo.Result_Set.ESrvc_Result[0].CPESrvcID}`,
  )
  console.log(`   ✓ CPEntID_SUB:  ${row.CPEntID_SUB}`)
  console.log(`   ✓ CPRole:       ${row.CPRole}`)
  console.log(`   ✓ Validity:     ${row.StartDate} → ${row.EndDate}`)

  console.log('\n=== ALL CHECKS PASSED ===\n')
})().catch((e) => {
  console.error('\n!!! TEST FAILED !!!')
  console.error(e.stack || e.message || e)
  process.exit(1)
})
