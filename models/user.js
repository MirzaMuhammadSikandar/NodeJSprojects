const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true},
    email: { type: String, required: true, unique: true },
    password: { type: String, default: null},
    dateofbirth: { type: String},
    address: { type: String},
    image: { type: String},
    otp: {type: Number},
    verified: {type: Boolean, default: false}
})

const model = mongoose.model('users', UserSchema);

module.exports = model