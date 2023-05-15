const { Schema, model } = require('mongoose')

const User = new Schema({
	"id": { "type": Number, "unique": true, "required": true },
	"phone_number": { "type": String, "unique": true, "required": true },
	"password": { "type": String, "required": true }
})

module.exports = model('User', User)