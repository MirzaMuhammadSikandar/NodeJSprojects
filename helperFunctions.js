const jwt = require('jsonwebtoken')
require('dotenv').config()

//----------------Helper Functions-------------------

function generateAccessToken(id, email) {
    return jwt.sign({ id, email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '3600s' })
}
//3600seconds = 60minutes


function generateRefreshToken(id, email) {
    return jwt.sign({ id, email }, process.env.REFRESH_TOKEN_SECRET)
}

module.exports = {
    generateAccessToken,
    generateRefreshToken
}