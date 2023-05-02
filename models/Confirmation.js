const { Schema, model } = require('mongoose')

const Confirmation = new Schema({
	"ip": { "type": String, "unique": true, "required": true },
	"phone_number": { "type": String, "unique": true, "required": true },
	"code": { "type": Number, "required": true },
	"datetime": { "type": Number, "required": true }
})

module.exports = model('Confirmation', Confirmation)