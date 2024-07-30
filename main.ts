#!/usr/bin/env -S deno run -A --unstable-hmr

import {copy} from 'jsr:@std/io'
import {parseAuthPassword} from "./utils.ts"

const bndAddr = new Uint8Array(4)
Deno.networkInterfaces().forEach((ni) => {
  if (ni.name === 'lo' && ni.address === '127.0.0.1') {
    ni.address.split('.').forEach((octet, i) => {
      bndAddr[i] = parseInt(octet)
    })
  }
})

const ENABLE_AUTH = true
const passwd = new Map<string, string>()
passwd.set('4ae1d8bfa6bd45d8', 'b4d7-8d453c61c25b')


enum AUTH_METHODS {
  NoAuthentication = 0x00,
  Password = 0x02,
  no_supported = 0xff,
}

const listener = Deno.listen({port: 80})

for await (const conn of listener) {
  // if (!conn.remoteAddr.hostname.startsWith('192.168.100.')) {
  //   console.log('pre close', conn.remoteAddr.hostname)
  //   conn.close()
  //   continue
  // }
  handleConnection(conn).catch((e) => {
    console.error(e)
  })
}

async function handleConnection(conn: Deno.TcpConn) {
  const buf = new Uint8Array(256)

  // Read client greeting
  let n = await conn.read(buf)
  if (buf.at(0) !== 0x05) {
    conn.close()
    return
  }

  // Send server greeting
  // await conn.write(new Uint8Array([0x05, 0x00]))

  // Send server greeting
  const methods = buf.subarray(2, n!)
  let method: number
  if (methods.includes(AUTH_METHODS.NoAuthentication) && !ENABLE_AUTH) {
    method = AUTH_METHODS.NoAuthentication
  } else if (methods.includes(AUTH_METHODS.Password)) {
    method = AUTH_METHODS.Password
  } else {
    method = AUTH_METHODS.no_supported
  }

  // console.log(`auth method: ${AUTH_METHODS[method]}`, buf.slice(0, 8))
  await conn.write(new Uint8Array([0x05, method]))
  if (method === AUTH_METHODS.no_supported) {
    conn.close()
    return
  }

  // Perform authentication if required
  if (method === AUTH_METHODS.Password) {
    const n = await conn.read(buf)

    // console.log({buf})
    // const u = new Uint8Array(buf, buf.at(1))
    // console.log({u})
    // // const u = new Uint8Array(buf, buf.at(1))

    // const usernameLen = buf.at(1) as number
    // const username = new TextDecoder().decode(buf.subarray(2, 2 + usernameLen))
    // const passwordLen = buf.at(2 + usernameLen) as number
    // const password = new TextDecoder().decode(
    //   buf.subarray(3 + usernameLen, 3 + usernameLen + passwordLen)
    // )

    // buf.subarray(2, 2 + usernameLen)
    // buf.subarray(3 + usernameLen, 3 + usernameLen + passwordLen)
    // console.log(`${usernameLen}, ${username}, ${passwordLen}, ${password}`)
    console.log(buf)
    const cred = parseAuthPassword(buf)
    if (passwd.get(cred.username) !== cred.password) {
      console.error(`login: ${cred.username}:${cred.password}`)
      await conn.write(new Uint8Array([0x01, 0x01]))
      conn.close()
      return
    }

    await conn.write(new Uint8Array([0x01, 0x00]))
  }

  // Read client request
  n = await conn.read(buf)
  if (buf[1] !== 0x01) {
    conn.close()
    return
  }

  const atyp = buf[3]
  let addr: string
  let port: number
  if (atyp === 0x01) {
    // IPv4 address
    addr = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`
    port = (buf[8] << 8) | buf[9]
  } else if (atyp === 0x03) {
    // Domain name
    const len = buf[4]
    addr = new TextDecoder().decode(buf.subarray(5, 5 + len))
    port = (buf[5 + len] << 8) | buf[6 + len]
  } else {
    // Unsupported address type
    await conn.write(new Uint8Array([0x05, 0x08, 0x00, atyp]))
    conn.close()
    return
  }

  // Connect to target server
  let targetConn: Deno.Conn
  try {
    targetConn = await Deno.connect({hostname: addr, port})
  } catch (e) {
    await conn.write(new Uint8Array([0x05, 0x05, 0x00, atyp]))
    conn.close()
    return
  }

  await conn.write(
    new Uint8Array([0x05, 0x00, 0x00, 0x01, ...bndAddr, 0x00, 0x50])
  )

  // console.log('bind conn')
  console.log(`conn from: ${conn.remoteAddr.hostname} to ${addr}:${port}`)
  try {
    await Promise.all([
      // Proxy data between client and target server
      copy(conn, targetConn),
      copy(targetConn, conn),
    ])
  } catch (e) {
    console.error(
      `error from: ${conn.remoteAddr.hostname} to ${addr}:${port}`,
      e.name,
      e.code
    )
  }

  conn.close()
  targetConn.close()
}
