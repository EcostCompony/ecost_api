const { Schema, model } = require('mongoose')

const Sequence = new Schema({
	"table": { "type": String, "unique": true, "required": true },
	"count": { "type": Number, "required": true }
})

module.exports = model('Sequence', Sequence)