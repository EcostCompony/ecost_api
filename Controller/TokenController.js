'use strict'

module.exports = (req, res, next) => {

	try {
		const response = require('./../response')

		require('passport').authenticate('jwt', { "session": false }, (error, user, info) => {
			if (error) return response.systemError(error, res)
			if (info && info.message === "No auth token") return response.error(3, "the access token was not transferred", [{ "key": 'Authorization', "value": 'required' }], res)
			if (!user) return response.error(4, "invalid access token", [{ "key": 'Authorization', "value": 'invalid' }], res)

			req.token_payload = user

			return next()
		})(req, res, next)
	} catch (error) {
		return response.systemError(error, res)
	}

}