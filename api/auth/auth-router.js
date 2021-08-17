// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const authRouter = express.Router()
const Users = require('../users/users-model')
const {checkPasswordLength, restricted, checkUsernameFree, checkUsernameExists} = require('./auth-middleware')
const bcrypt = require('bcryptjs')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
authRouter.post('/register', 
  checkUsernameFree, 
  checkPasswordLength, 
  async (req, res, next) => {
    try{
      const {username, password} = req.body
      const hash = bcrypt.hashSync(password)
      const user = { username, password: hash}
      const post = await Users.add(req.body)
      res.status(201).json(post)
    }catch(e){
      next(e)
    }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
authRouter.post('/login', checkUsernameExists, async (req, res, next) => {
  try{
    const {username, password} = req.body
    const [user] = await Users.findBy({username})

    if(user && bcrypt.compareSync(password, user.password)){
      req.session.user = user
      res.json({message: `Welcome ${username}!`})
    }else{
      next({ status: 401, message: "Invalid credentials" })
    }
  }catch(e){
    next(e)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
authRouter.get('/logout', async (req, res, next) => {
  if(req.session.user) {
    req.session.destroy(err => {
      if(err) {
        res.json({message: 'sorry, you cannot leave'})
      }else{
        res.json({ message: 'bye'})
      }
    })
  }else{
    res.json({message: 'but i do not know you'})
  }
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = authRouter