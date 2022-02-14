require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const res = require('express/lib/response')
const User = require('./models/User')

const app = express()

app.use(express.json())

app.get('/', (request, response) => {
  return response.status(200).json({ msg: 'Bem vindo a nossa API!' })
})

app.post('/auth/register', async (request, response) => {

  const { name, email, password, confirmPassword } = request.body

  if (!name) {
    return response.status(422).json({ msg: 'O nome é obrigatório!' })
  }

  if (!email) {
    return response.status(422).json({ msg: 'O e-mail é obrigatório!' })
  }

  if (!password) {
    return response.status(422).json({ msg: 'A senha é obrigatória!' })
  }

  if (password !== confirmPassword) {
    return response.status(422).json({ msg: 'As senhas não conferem!' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password,salt)
  
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {

    await user.save()

    response.status(201).json({ msg: 'Usuário criado com sucesso!'})

  } catch (error) {
    console.log(error)
    response
    .status(500)
    .json({
      msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'
    })
  }

})

const db_url = process.env.DB_URL

mongoose
.connect(db_url)
.then(() => {
  app.listen(3000,() => {
    console.log('Api running in the port: 3000')
  })
})