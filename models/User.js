const { Schema, model } = require('mongoose')

const User = new Schema({
	"phone_number": { "type": String, "unique": true, "required": true },
	"password": { "type": String, "required": true },
	"services": [String]
})

module.exports = model('User', User)