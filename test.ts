#!/usr/bin/env -S deno test -A --watch

import {assertEquals} from 'jsr:@std/assert/equals'
import {parseAuthPassword} from './utils.ts'

const enc = new TextEncoder()

Deno.test('parse', () => {
  const username = enc.encode('4ae1d8bfa6bd45d8')
  const password = enc.encode('b4d7-8d453c61c25b')

  const buf = Uint8Array.from([
    1, // ver
    username.byteLength,
    ...username,
    password.byteLength,
    ...password,
  ])
  // const buf = Uint8Array.from([
  //   1, // ver
  //   16, // username len
  //   52, 97, 101, 49, 100, 56, 98, 102, 97, 54, 98, 100, 52, 53, 100, 56,
  //   17, // password len
  //   98, 52, 100, 55, 45, 56, 100, 52, 53, 51, 99, 54, 49, 99, 50, 53, 98, 0,
  //   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  // ])

  assertEquals(parseAuthPassword(buf), {
    username: '4ae1d8bfa6bd45d8',
    password: 'b4d7-8d453c61c25b',
  })
})
