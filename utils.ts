const decoder = new TextDecoder()

const usernameLenOffset = 1

export const parseAuthPassword = (buf: Uint8Array) => {
  const username = new Uint8Array(
    buf.buffer,
    usernameLenOffset + 1,
    buf.at(usernameLenOffset)
  )
  const password = new Uint8Array(
    buf.buffer,
    username.byteLength + usernameLenOffset + 2,
    buf.at(username.byteLength + usernameLenOffset + 1)
  )
  return {
    username: decoder.decode(username),
    password: decoder.decode(password),
  }
}
