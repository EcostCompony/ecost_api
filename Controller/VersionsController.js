'use strict'

module.exports = (req, res, next) => {

	const response = require('./../response')

	try {
		let v = req.query.v
		return !v || v !== '1.0' ? response.error(6, "invalid request", [{ "key": 'v', "value": v ? v : 'required' }], res) : next()
	} catch (error) {
		return response.systemError(error, res)
	}

}