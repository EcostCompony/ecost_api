'use strict'

module.exports = app => {

	const tokenController = require('./../Controller/TokenController')
	const versionsController = require('./../Controller/VersionsController')
	const signupController = require('./../Controller/SignupController')
	const signinController = require('./../Controller/SigninController')

	//	auth / signup
	app.route('/api/auth/method/signup.confirmPhoneNumber').all(versionsController, signupController.confirmPhoneNumber)
	app.route('/api/auth/method/signup.checkConfirmCode').all(tokenController, versionsController, signupController.checkConfirmCode)
	app.route('/api/auth/method/signup').all(tokenController, versionsController, signupController.signup)

	// auth / signin
	app.route('/api/auth/method/signin').all(versionsController, signinController.signin)
	app.route('/api/auth/method/signin.checkConfirmCode').all(tokenController, versionsController, signinController.checkConfirmCode)

	app.all('*', (req, res, next) => {

		const response = require('./../response')

		try {
			return response.error(2, "not found", [{ "key": 'URL', "value": req.originalUrl }], res)
		} catch (error) {
			return response.systemError(error, res)
		}

	})

}