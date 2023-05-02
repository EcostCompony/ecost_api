'use strict'

exports.send = (values, res) => res.status(200).json({ "res": values }).end()

exports.error = (code, message, details, res) => {

	res.status(400).json({
		"error": {
			"error_code": code,
			"error_msg": message,
			"error_details": details
		}
	}).end()

}

exports.systemError = (error, res) => {

	console.log(error)
	res.status(400).json({
		"error": {
			"error_code": 1,
			"error_msg": "unknown error"
		}
	}).end()

}