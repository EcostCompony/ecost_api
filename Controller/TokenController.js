'use strict'

const response = require('./../response')
const passport = require('passport')

exports.control = (req, res, next) => {

	passport.authenticate('jwt', { "session": false }, (error, user, info) => {
		if (error) return response.systemError(error, res)
		if (info && info.message === "No auth token") return response.error(2, "the access token was not transferred", [{ "key": 'Authorization', "value": 'required' }], res)
		if (!user) return response.error(3, "invalid access token", [{ "key": 'Authorization', "value": 'invalid' }], res)

		req.token_payload = user
		return next()
	})(req, res, next)

}