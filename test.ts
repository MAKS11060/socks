#!/usr/bin/env -S deno test -A --watch

import {assertEquals} from 'jsr:@std/assert/equals'
import {parseAuthPassword} from './utils.ts'

Deno.test('parse', () => {
  const buf = Uint8Array.from([
    1, //
    16, 52, 97, 101, 49, 100, 56, 98, 102, 97, 54, 98, 100, 52, 53, 100, 56,
    17, 98, 52, 100, 55, 45, 56, 100, 52, 53, 51, 99, 54, 49, 99, 50, 53, 98, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ])
  assertEquals(parseAuthPassword(buf), {
    username: '4ae1d8bfa6bd45d8',
    password: 'b4d7-8d453c61c25b',
  })
})

Deno.test('parse', () => {
  const buf = Uint8Array.from([
    1,
    16, 52, 97, 101, 49, 100, 56, 98, 102, 97, 54, 98, 100, 52, 53, 100, 56,
    17, 98, 52, 100, 55, 45, 56, 100, 52, 53, 51, 99, 54, 49, 99, 50, 53, 98, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ])
  assertEquals(parseAuthPassword(buf), {
    username: '4ae1d8bfa6bd45d8',
    password: 'b4d7-8d453c61c25b',
  })
})
