'use strict'

const Sequence = require('./../models/Sequence')

exports.getNextSequence = async (table) => {

	var seq = await Sequence.findOne({ "table": table })
	await Sequence.findOneAndUpdate({ "table": table }, { "count": seq.count + 1 })
	return seq.count + 1

}