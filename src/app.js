require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const res = require('express/lib/response')
const User = require('./models/User')
const cors = require('cors')

const app = express()

app.use(cors())
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

app.post('/auth/user', async (request, response) => {

  const { email, password } = request.body

  if (!email) {
    return response.status(422).json({ msg: 'O e-mail é obrigatório!' })
  }

  if (!password) {
    return response.status(422).json({ msg: 'A senha é obrigatória!' })
  }

  const user = await User.findOne({ email: email})

  if(!user) {
    return response.status(422).json({ msg: 'Usuário não encontrado!' })
  }

  const checkPassword = await bcrypt.compare(password, user.password)

  if (!checkPassword) {
    return response.status(422).json({ msg: 'A senha não conferem!' })
  }

  try {
    const secret = process.env.JWT_SECRET
    const token = jwt.sign(
      {
        user: user._id
      },
      secret,
    )

    return response.status(200).json({ msg: 'Autenticação realizada com sucesso', user, token })

  } catch (error) {
    console.log(error)
    response
    .status(500)
    .json({
      msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'
    })
  }

})

app.get('/user/:id', checkToken, async(request, response) => {

  const id = request.params.id

  const user = await User.findById(id, '-password')

  if (!user) {
    return response.status(422).json({ msg: 'O usuário não encontrado!' })
  }

  return response.status(200).json({ data: user })

})

function checkToken (request, response, next) {

  const authHeader = request.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return response.status(401).json({ msg: 'Acesso negado!' })
  }

  try {

    const secret = process.env.JWT_SECRET

    jwt.verify(token, secret)
    next()
    
  } catch (error) {
    response.status(400).json({ msg: 'Token inválido!' })
  }

}

const db_url = process.env.DB_URL

mongoose
.connect(db_url)
.then(() => {
  app.listen(3000,() => {
    console.log('Api running in the port: 3000')
  })
})