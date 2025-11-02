const users = new Map()
let botInstance = null

const getUser = uid => {
  if (!users.has(uid)) {
    users.set(uid, {
      accounts: new Map(),
      active: null
    })
  }
  return users.get(uid)
}

const getAcc = uid => {
  const user = getUser(uid)
  return user.active ? user.accounts.get(user.active) : null
}

const setBot = bot => {
  botInstance = bot
}

const getBot = () => botInstance

module.exports = {
  getUser,
  getAcc,
  setBot,
  getBot,
  users
}